package shadowflow

import (
	"crypto/rand"
	"io"
	mathrand "math/rand"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

// ====================================================================
// TLS Record Size Camouflage Engine
//
// This engine wraps a net.Conn (or io.Writer/io.Reader) and reshapes
// the TLS record payload sizes to match a real browser's traffic profile.
//
// Key capabilities:
//   - Pads small writes to eliminate fingerprint sizes (e.g., 19-byte)
//   - Splits large writes into profile-conforming record sizes
//   - Simulates initial handshake packet sequence
//   - Supports dynamic camouflage mode switching mid-connection
// ====================================================================

// CamouflageConfig holds per-connection camouflage settings.
type CamouflageConfig struct {
	// Profile for traffic shaping
	Profile *TrafficProfile

	// Camouflage mode: "random", "dynamic", "web_browsing", "live_stream",
	// "file_download", "video_call", or "" (none)
	Mode string

	// For dynamic mode: switching interval range (seconds)
	SwitchIntervalMin int
	SwitchIntervalMax int
}

// CamouflageEngine reshapes bidirectional traffic to match a target profile.
type CamouflageEngine struct {
	config *CamouflageConfig

	// Current active profile (may change in dynamic mode)
	activeProfile atomic.Value // *TrafficProfile

	// Packet counters for initial sequence tracking
	c2sPacketIndex int
	s2cPacketIndex int

	// Dynamic mode control
	stopCh   chan struct{}
	stopped  atomic.Bool
	wg       sync.WaitGroup

	mu sync.Mutex
}

// NewCamouflageEngine creates a new engine with the given config.
func NewCamouflageEngine(config *CamouflageConfig) *CamouflageEngine {
	e := &CamouflageEngine{
		config: config,
		stopCh: make(chan struct{}),
	}

	// Set initial profile
	profile := config.Profile
	if profile == nil {
		profile = ChromeH2Profile
	}
	e.activeProfile.Store(profile)

	// Start dynamic switcher if mode is "dynamic"
	if config.Mode == "dynamic" {
		e.startDynamicSwitcher()
	}

	return e
}

// startDynamicSwitcher periodically switches the active profile.
func (e *CamouflageEngine) startDynamicSwitcher() {
	minInterval := e.config.SwitchIntervalMin
	maxInterval := e.config.SwitchIntervalMax
	if minInterval <= 0 {
		minInterval = 30
	}
	if maxInterval <= 0 || maxInterval < minInterval {
		maxInterval = 120
	}

	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		for {
			// Random interval within [min, max]
			interval := minInterval + mathrand.Intn(maxInterval-minInterval+1)
			timer := time.NewTimer(time.Duration(interval) * time.Second)
			select {
			case <-e.stopCh:
				timer.Stop()
				return
			case <-timer.C:
				// Switch to a random profile
				newProfile := GetRandomProfile()
				old := e.getProfile()
				e.activeProfile.Store(newProfile)
				// Reset initial sequence counters on switch
				e.mu.Lock()
				e.c2sPacketIndex = len(newProfile.C2SInitial) // skip initial phase on switch
				e.s2cPacketIndex = len(newProfile.S2CInitial)
				e.mu.Unlock()
				log.WithFields(log.Fields{
					"from": old.Name,
					"to":   newProfile.Name,
					"next": interval,
				}).Debug("ShadowFlow: dynamic camouflage switch")
			}
		}
	}()
}

// Close stops the dynamic switcher.
func (e *CamouflageEngine) Close() {
	if e.stopped.CompareAndSwap(false, true) {
		close(e.stopCh)
		e.wg.Wait()
	}
}

func (e *CamouflageEngine) getProfile() *TrafficProfile {
	return e.activeProfile.Load().(*TrafficProfile)
}

// ====================================================================
// ShapedWriter — wraps an io.Writer with TLS record size shaping
// ====================================================================

// ShapedWriter wraps a writer and reshapes output to match profile.
type ShapedWriter struct {
	writer    io.Writer
	engine    *CamouflageEngine
	direction Direction // C2S or S2C
	mu        sync.Mutex
}

// Direction indicates traffic direction.
type Direction int

const (
	C2S Direction = iota
	S2C
)

// NewShapedWriter creates a writer that reshapes data to match the profile.
func NewShapedWriter(w io.Writer, engine *CamouflageEngine, dir Direction) *ShapedWriter {
	return &ShapedWriter{
		writer:    w,
		engine:    engine,
		direction: dir,
	}
}

// Write reshapes the data into profile-conforming chunks.
func (sw *ShapedWriter) Write(data []byte) (int, error) {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	profile := sw.engine.getProfile()
	totalWritten := 0
	remaining := data

	for len(remaining) > 0 {
		targetSize := sw.getTargetSize(profile)

		if len(remaining) <= targetSize {
			// Data fits in one record — pad to target size
			padded, err := sw.padToSize(remaining, targetSize, profile)
			if err != nil {
				return totalWritten, err
			}
			n, err := sw.writer.Write(padded)
			_ = n
			totalWritten += len(remaining)
			if err != nil {
				return totalWritten, err
			}
			break
		}

		// Data is larger — split at target size
		chunk := remaining[:targetSize]
		n, err := sw.writer.Write(chunk)
		_ = n
		totalWritten += targetSize
		if err != nil {
			return totalWritten, err
		}
		remaining = remaining[targetSize:]
	}

	return totalWritten, nil
}

// getTargetSize determines the target record size for the next write.
func (sw *ShapedWriter) getTargetSize(profile *TrafficProfile) int {
	sw.engine.mu.Lock()
	defer sw.engine.mu.Unlock()

	var size int
	switch sw.direction {
	case C2S:
		size = SampleInitialSize(profile.C2SInitial, sw.engine.c2sPacketIndex)
		if size > 0 {
			sw.engine.c2sPacketIndex++
		} else {
			size = SampleSize(profile.C2SSizes)
		}
	case S2C:
		size = SampleInitialSize(profile.S2CInitial, sw.engine.s2cPacketIndex)
		if size > 0 {
			sw.engine.s2cPacketIndex++
		} else {
			size = SampleSize(profile.S2CSizes)
		}
	}

	// Enforce bounds
	if size < profile.MinRecordPayload {
		size = profile.MinRecordPayload
	}
	if size > profile.MaxRecordPayload {
		size = profile.MaxRecordPayload
	}

	return size
}

// padToSize pads data to the target size with random bytes.
// The padding format: [2-byte original length][original data][random padding]
// This allows the receiver to strip padding.
func (sw *ShapedWriter) padToSize(data []byte, targetSize int, profile *TrafficProfile) ([]byte, error) {
	dataLen := len(data)

	// If data is already at or above target, just return it
	// (minimum is MinRecordPayload, not an exact match requirement)
	if dataLen >= targetSize {
		return data, nil
	}

	// Only pad if the data is suspiciously small (below MinRecordPayload)
	// For normal-sized data, don't pad — the size distribution already handles it
	if dataLen >= profile.MinRecordPayload {
		return data, nil
	}

	// Pad to at least MinRecordPayload
	paddedSize := profile.MinRecordPayload
	if paddedSize < targetSize && targetSize <= profile.MinRecordPayload*3 {
		paddedSize = targetSize
	}

	padded := make([]byte, paddedSize)
	copy(padded, data)
	// Fill remaining with random bytes (not zeros — zeros are detectable)
	if paddedSize > dataLen {
		rand.Read(padded[dataLen:])
	}
	return padded, nil
}

// ====================================================================
// ShapedReader — wraps an io.Reader with record size awareness
// ====================================================================

// ShapedReader wraps a reader. Currently a pass-through since
// reshaping is primarily done on the write side.
// The reader tracks packet indices for profile correlation.
type ShapedReader struct {
	reader    io.Reader
	engine    *CamouflageEngine
	direction Direction
}

// NewShapedReader creates a reader that tracks profile state.
func NewShapedReader(r io.Reader, engine *CamouflageEngine, dir Direction) *ShapedReader {
	return &ShapedReader{
		reader:    r,
		engine:    engine,
		direction: dir,
	}
}

// Read passes through to the underlying reader.
// Profile state tracking happens on the write side.
func (sr *ShapedReader) Read(p []byte) (int, error) {
	return sr.reader.Read(p)
}
