package shadowflow

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	mathrand "math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ====================================================================
// ShadowStream Transport Protocol
//
// A custom multiplexed transport that sits inside TLS (Reality).
// Unlike WebSocket/gRPC, it produces ZERO protocol-level fingerprints.
//
// Frame format (all encrypted by outer TLS):
//   +--------+--------+----------+--------+---------+
//   | Type   | Flags  | StreamID | Length | Payload |
//   | 1 byte | 1 byte | 2 bytes  | 2 bytes| N bytes |
//   +--------+--------+----------+--------+---------+
//
// Design principles:
//   1. DATA and PADDING frames are indistinguishable after encryption
//   2. No magic bytes, no version negotiation, no HTTP upgrade
//   3. Frame sizes are shaped by the camouflage engine
//   4. Built-in heartbeat that mimics real data patterns
//   5. Multiplexed streams over a single TLS connection
// ====================================================================

// Frame types
const (
	FrameData        byte = 0x00 // Real user data
	FramePadding     byte = 0x01 // Camouflage padding (indistinguishable from DATA when encrypted)
	FrameStreamOpen  byte = 0x02 // Open a new sub-stream
	FrameStreamClose byte = 0x03 // Close a sub-stream
	FrameHeartbeat   byte = 0x04 // Keep-alive (sized to look like real data)
	FrameShapeSwitch byte = 0x05 // Signal camouflage profile switch to peer
)

// Frame flags
const (
	FlagNone     byte = 0x00
	FlagFin      byte = 0x01 // Final frame for this stream
	FlagPriority byte = 0x02 // High-priority frame
)

// Frame header size: Type(1) + Flags(1) + StreamID(2) + Length(2) = 6
const FrameHeaderSize = 6

// Maximum frame payload size (bounded by uint16 Length field)
const MaxFramePayload = 65535

// Frame represents a ShadowStream protocol frame.
type Frame struct {
	Type     byte
	Flags    byte
	StreamID uint16
	Payload  []byte
}

// MarshalBinary serializes a frame to wire format.
func (f *Frame) MarshalBinary() ([]byte, error) {
	payloadLen := len(f.Payload)
	if payloadLen > MaxFramePayload {
		return nil, fmt.Errorf("payload too large: %d > %d", payloadLen, MaxFramePayload)
	}
	data := make([]byte, FrameHeaderSize+payloadLen)
	data[0] = f.Type
	data[1] = f.Flags
	binary.BigEndian.PutUint16(data[2:4], f.StreamID)
	binary.BigEndian.PutUint16(data[4:6], uint16(payloadLen))
	if payloadLen > 0 {
		copy(data[FrameHeaderSize:], f.Payload)
	}
	return data, nil
}

// ReadFrame reads one frame from the connection.
func ReadFrame(r io.Reader) (*Frame, error) {
	header := make([]byte, FrameHeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	f := &Frame{
		Type:     header[0],
		Flags:    header[1],
		StreamID: binary.BigEndian.Uint16(header[2:4]),
	}
	payloadLen := binary.BigEndian.Uint16(header[4:6])
	if payloadLen > 0 {
		f.Payload = make([]byte, payloadLen)
		if _, err := io.ReadFull(r, f.Payload); err != nil {
			return nil, err
		}
	}
	return f, nil
}

// ====================================================================
// ShadowStream Connection — multiplexed connection over TLS
// ====================================================================

// Stream represents a single multiplexed sub-stream.
type Stream struct {
	id       uint16
	conn     *ShadowStreamConn
	readBuf  chan []byte // buffered data chunks
	readPart []byte     // partially consumed chunk
	closed   atomic.Bool
}

func (s *Stream) Read(p []byte) (int, error) {
	// First consume any partial chunk
	if len(s.readPart) > 0 {
		n := copy(p, s.readPart)
		s.readPart = s.readPart[n:]
		return n, nil
	}
	// Wait for next chunk
	chunk, ok := <-s.readBuf
	if !ok {
		return 0, io.EOF
	}
	n := copy(p, chunk)
	if n < len(chunk) {
		s.readPart = chunk[n:]
	}
	return n, nil
}

func (s *Stream) Write(p []byte) (int, error) {
	if s.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	return s.conn.writeData(s.id, p)
}

func (s *Stream) Close() error {
	if s.closed.CompareAndSwap(false, true) {
		_ = s.conn.writeControl(FrameStreamClose, s.id, nil)
		close(s.readBuf)
	}
	return nil
}

// ShadowStreamConn manages a multiplexed connection over a single net.Conn.
type ShadowStreamConn struct {
	conn   net.Conn
	engine *CamouflageEngine

	streams   sync.Map // map[uint16]*Stream
	nextID    atomic.Uint32
	acceptCh  chan *Stream

	writeMu sync.Mutex // serialize writes to underlying conn
	closed  atomic.Bool
	stopCh  chan struct{}
	wg      sync.WaitGroup

	// Heartbeat / padding control
	heartbeatInterval time.Duration
}

// NewShadowStreamConn wraps a net.Conn with ShadowStream multiplexing.
func NewShadowStreamConn(conn net.Conn, engine *CamouflageEngine, isServer bool) *ShadowStreamConn {
	sc := &ShadowStreamConn{
		conn:              conn,
		engine:            engine,
		acceptCh:          make(chan *Stream, 32),
		stopCh:            make(chan struct{}),
		heartbeatInterval: 15 * time.Second,
	}
	// Server uses even IDs, client uses odd IDs
	if isServer {
		sc.nextID.Store(2)
	} else {
		sc.nextID.Store(1)
	}

	// Start read loop and heartbeat
	sc.wg.Add(2)
	go sc.readLoop()
	go sc.heartbeatLoop()

	return sc
}

// OpenStream creates a new sub-stream.
func (sc *ShadowStreamConn) OpenStream() (*Stream, error) {
	if sc.closed.Load() {
		return nil, io.ErrClosedPipe
	}
	id := uint16(sc.nextID.Add(2) - 2)
	s := &Stream{
		id:      id,
		conn:    sc,
		readBuf: make(chan []byte, 64),
	}
	sc.streams.Store(id, s)

	if err := sc.writeControl(FrameStreamOpen, id, nil); err != nil {
		sc.streams.Delete(id)
		return nil, err
	}
	return s, nil
}

// AcceptStream waits for a new incoming sub-stream.
func (sc *ShadowStreamConn) AcceptStream() (*Stream, error) {
	s, ok := <-sc.acceptCh
	if !ok {
		return nil, io.ErrClosedPipe
	}
	return s, nil
}

// Close shuts down the connection and all streams.
func (sc *ShadowStreamConn) Close() error {
	if sc.closed.CompareAndSwap(false, true) {
		close(sc.stopCh)
		close(sc.acceptCh)
		sc.streams.Range(func(key, value any) bool {
			if s, ok := value.(*Stream); ok {
				s.closed.Store(true)
				select {
				case <-s.readBuf:
				default:
				}
			}
			return true
		})
		sc.wg.Wait()
		return sc.conn.Close()
	}
	return nil
}

// readLoop processes incoming frames and dispatches to streams.
func (sc *ShadowStreamConn) readLoop() {
	defer sc.wg.Done()
	for {
		frame, err := ReadFrame(sc.conn)
		if err != nil {
			if !sc.closed.Load() {
				sc.Close()
			}
			return
		}

		switch frame.Type {
		case FrameData:
			if v, ok := sc.streams.Load(frame.StreamID); ok {
				s := v.(*Stream)
				if !s.closed.Load() {
					select {
					case s.readBuf <- frame.Payload:
					default:
						// Buffer full, drop (backpressure)
					}
				}
			}

		case FramePadding:
			// Silently discard — this is camouflage
			continue

		case FrameStreamOpen:
			s := &Stream{
				id:      frame.StreamID,
				conn:    sc,
				readBuf: make(chan []byte, 64),
			}
			sc.streams.Store(frame.StreamID, s)
			select {
			case sc.acceptCh <- s:
			default:
			}

		case FrameStreamClose:
			if v, ok := sc.streams.LoadAndDelete(frame.StreamID); ok {
				s := v.(*Stream)
				s.closed.Store(true)
				// Don't close readBuf here — let remaining data drain
			}

		case FrameHeartbeat:
			// Heartbeat — no action needed (already consumed as traffic)
			continue

		case FrameShapeSwitch:
			// Peer signals a profile switch
			if len(frame.Payload) > 0 {
				profileName := string(frame.Payload)
				if p := GetProfile(profileName); p != nil {
					sc.engine.activeProfile.Store(p)
				}
			}
		}
	}
}

// heartbeatLoop sends periodic heartbeats that look like real data.
func (sc *ShadowStreamConn) heartbeatLoop() {
	defer sc.wg.Done()
	for {
		// Randomize interval ±30% to avoid periodicity detection
		jitter := time.Duration(mathrand.Int63n(int64(sc.heartbeatInterval) * 6 / 10))
		interval := sc.heartbeatInterval - time.Duration(sc.heartbeatInterval*3/10) + jitter

		timer := time.NewTimer(interval)
		select {
		case <-sc.stopCh:
			timer.Stop()
			return
		case <-timer.C:
			profile := sc.engine.getProfile()
			// Heartbeat size matches profile distribution (looks like real data)
			size := SampleSize(profile.S2CSizes)
			if size < profile.MinRecordPayload {
				size = profile.MinRecordPayload
			}
			if size > 1024 {
				size = 1024 // cap heartbeat payload
			}
			payload := make([]byte, size)
			rand.Read(payload)
			_ = sc.writeControl(FrameHeartbeat, 0, payload)
		}
	}
}

// writeData sends a DATA frame, shaped by the camouflage engine.
func (sc *ShadowStreamConn) writeData(streamID uint16, data []byte) (int, error) {
	sc.writeMu.Lock()
	defer sc.writeMu.Unlock()

	profile := sc.engine.getProfile()
	totalWritten := 0
	remaining := data

	for len(remaining) > 0 {
		// Determine target record size from profile
		targetSize := SampleSize(profile.C2SSizes)
		if targetSize < profile.MinRecordPayload {
			targetSize = profile.MinRecordPayload
		}
		// Cap by max frame payload and remaining data
		chunkSize := targetSize - FrameHeaderSize
		if chunkSize > len(remaining) {
			chunkSize = len(remaining)
		}
		if chunkSize > MaxFramePayload {
			chunkSize = MaxFramePayload
		}

		frame := &Frame{
			Type:     FrameData,
			Flags:    FlagNone,
			StreamID: streamID,
			Payload:  remaining[:chunkSize],
		}

		wireData, err := frame.MarshalBinary()
		if err != nil {
			return totalWritten, err
		}

		if _, err := sc.conn.Write(wireData); err != nil {
			return totalWritten, err
		}

		totalWritten += chunkSize
		remaining = remaining[chunkSize:]

		// Occasionally inject a padding frame (10-30% chance)
		if mathrand.Intn(100) < 20 {
			sc.injectPadding(profile)
		}
	}

	return totalWritten, nil
}

// writeControl sends a control frame.
func (sc *ShadowStreamConn) writeControl(frameType byte, streamID uint16, payload []byte) error {
	sc.writeMu.Lock()
	defer sc.writeMu.Unlock()

	frame := &Frame{
		Type:     frameType,
		Flags:    FlagNone,
		StreamID: streamID,
		Payload:  payload,
	}

	wireData, err := frame.MarshalBinary()
	if err != nil {
		return err
	}
	_, err = sc.conn.Write(wireData)
	return err
}

// injectPadding sends a padding frame that looks identical to a DATA frame.
func (sc *ShadowStreamConn) injectPadding(profile *TrafficProfile) {
	size := SampleSize(profile.C2SSizes)
	if size < profile.MinRecordPayload {
		size = profile.MinRecordPayload
	}
	if size > 2048 {
		size = 2048 // reasonable padding cap
	}
	payload := make([]byte, size)
	rand.Read(payload)

	frame := &Frame{
		Type:     FramePadding,
		Flags:    FlagNone,
		StreamID: 0, // padding uses stream 0 (reserved)
		Payload:  payload,
	}
	wireData, _ := frame.MarshalBinary()
	sc.conn.Write(wireData)
}
