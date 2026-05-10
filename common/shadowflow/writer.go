package shadowflow

import (
	"github.com/xtls/xray-core/common/buf"
)

// ====================================================================
// Xray buf.Writer Adapter
//
// Integrates the TLS Record Size camouflage engine into Xray's
// buf.Writer pipeline. This is injected into the dispatcher's
// link chain, sitting between the inbound handler and outbound handler.
//
// Data flow:
//   Client → TLS(Reality) → Xray Inbound → [ShapedBufWriter] → Outbound
//   Outbound → [ShapedBufWriter] → Xray Inbound → TLS(Reality) → Client
// ====================================================================

// ShapedBufWriter wraps an Xray buf.Writer with camouflage shaping.
// It reshapes MultiBuffer writes to conform to the active traffic profile.
type ShapedBufWriter struct {
	writer buf.Writer
	engine *CamouflageEngine
	dir    Direction
}

// NewShapedBufWriter creates a buf.Writer adapter with traffic shaping.
func NewShapedBufWriter(writer buf.Writer, engine *CamouflageEngine, dir Direction) buf.Writer {
	return &ShapedBufWriter{
		writer: writer,
		engine: engine,
		dir:    dir,
	}
}

// WriteMultiBuffer implements buf.Writer.
// It reshapes the buffer sizes to match the traffic profile before passing through.
func (w *ShapedBufWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	profile := w.engine.getProfile()

	// Calculate total data length
	totalLen := mb.Len()
	if totalLen == 0 {
		return w.writer.WriteMultiBuffer(mb)
	}

	// Collect all data into a contiguous slice for reshaping
	data := make([]byte, 0, totalLen)
	for _, b := range mb {
		data = append(data, b.Bytes()...)
	}
	buf.ReleaseMulti(mb)

	// Reshape into profile-conforming chunks
	var shaped buf.MultiBuffer
	offset := 0
	for offset < len(data) {
		targetSize := w.getTargetSize(profile)
		if targetSize <= 0 {
			targetSize = profile.MinRecordPayload
		}

		chunkEnd := offset + targetSize
		if chunkEnd > len(data) {
			chunkEnd = len(data)
		}

		chunk := data[offset:chunkEnd]
		chunkLen := len(chunk)

		// Pad if below minimum record size to eliminate fingerprint sizes
		if chunkLen < profile.MinRecordPayload && offset+chunkLen >= len(data) {
			// This is the last (and small) chunk — pad it
			padded := w.padChunk(chunk, profile)
			b := buf.New()
			b.Write(padded)
			shaped = append(shaped, b)
		} else {
			b := buf.New()
			b.Write(chunk)
			shaped = append(shaped, b)
		}

		offset = chunkEnd
	}

	return w.writer.WriteMultiBuffer(shaped)
}

// Close implements common.Closable.
func (w *ShapedBufWriter) Close() error {
	if closer, ok := w.writer.(interface{ Close() error }); ok {
		return closer.Close()
	}
	return nil
}

// getTargetSize determines the next chunk size from the profile.
func (w *ShapedBufWriter) getTargetSize(profile *TrafficProfile) int {
	w.engine.mu.Lock()
	defer w.engine.mu.Unlock()

	var size int
	switch w.dir {
	case C2S:
		size = SampleInitialSize(profile.C2SInitial, w.engine.c2sPacketIndex)
		if size > 0 {
			w.engine.c2sPacketIndex++
		} else {
			size = SampleSize(profile.C2SSizes)
		}
	case S2C:
		size = SampleInitialSize(profile.S2CInitial, w.engine.s2cPacketIndex)
		if size > 0 {
			w.engine.s2cPacketIndex++
		} else {
			size = SampleSize(profile.S2CSizes)
		}
	}

	if size < profile.MinRecordPayload {
		size = profile.MinRecordPayload
	}
	if size > profile.MaxRecordPayload {
		size = profile.MaxRecordPayload
	}

	return size
}

// padChunk pads a small chunk to at least MinRecordPayload bytes.
func (w *ShapedBufWriter) padChunk(data []byte, profile *TrafficProfile) []byte {
	if len(data) >= profile.MinRecordPayload {
		return data
	}
	// Pad with random-looking bytes
	padded := make([]byte, profile.MinRecordPayload)
	copy(padded, data)
	// Use a simple XOR pattern for padding (fast, non-zero)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(i*7 + 13)
	}
	return padded
}
