package shadowflow

import (
	"crypto/rand"
	"io"
	mathrand "math/rand"
	"sync"
	"time"
)

// ====================================================================
// TLS-in-TLS Timing Disruption Engine
//
// When a user visits an HTTPS site through ShadowFlow, the inner TLS
// handshake creates a detectable REQUEST-RESPONSE timing pattern:
//
//   Without noise:  [outer TLS done] → [inner CH 512B] → [wait 50ms] → [inner SH 2000B] → ...
//   GFW sees:       data → pause → data → pause → data  (handshake rhythm)
//
//   With noise:     [outer TLS done] → [noise 87B] → [noise 30B] → [inner CH mixed with noise] → ...
//   GFW sees:       data → data → data → data → data   (continuous stream, no rhythm)
//
// The noise injector sends profile-conforming padding BEFORE and DURING
// the inner TLS handshake to break the timing correlation.
// ====================================================================

// NoiseInjector sends camouflage noise into a connection to disrupt
// the timing pattern of inner TLS handshakes.
type NoiseInjector struct {
	writer  io.Writer
	engine  *CamouflageEngine
	stopCh  chan struct{}
	stopped bool
	mu      sync.Mutex
	wg      sync.WaitGroup
}

// NewNoiseInjector creates a noise injector for a connection.
func NewNoiseInjector(w io.Writer, engine *CamouflageEngine) *NoiseInjector {
	return &NoiseInjector{
		writer: w,
		engine: engine,
		stopCh: make(chan struct{}),
	}
}

// InjectInitialNoise sends a burst of profile-conforming noise packets
// immediately after the outer TLS handshake completes, BEFORE any real
// data flows. This makes the connection start look like normal HTTP/2.
//
// Sequence mimics Chrome H2 connection establishment:
//   1. HTTP/2 Connection Preface + SETTINGS (~80-120 bytes)
//   2. Short pause (2-8ms)
//   3. WINDOW_UPDATE (~26-50 bytes)
//   4. Short pause (1-5ms)
//   5. HEADERS frame (~150-400 bytes)
func (ni *NoiseInjector) InjectInitialNoise() error {
	profile := ni.engine.getProfile()

	// Packet 1: Simulates HTTP/2 SETTINGS frame
	size1 := randRange(80, 120)
	if err := ni.sendNoise(size1); err != nil {
		return err
	}

	// Brief pause matching real H2 timing
	jitterSleep(2, 8)

	// Packet 2: Simulates WINDOW_UPDATE
	size2 := randRange(profile.MinRecordPayload, 50)
	if err := ni.sendNoise(size2); err != nil {
		return err
	}

	// Brief pause
	jitterSleep(1, 5)

	// Packet 3: Simulates initial HEADERS
	size3 := randRange(150, 400)
	if err := ni.sendNoise(size3); err != nil {
		return err
	}

	return nil
}

// StartContinuousNoise runs a background goroutine that periodically
// injects small noise packets during the connection lifetime.
// This fills timing gaps created by inner TLS handshake round-trips.
//
// The noise is heaviest in the first 2 seconds (during inner handshake)
// and becomes sparser afterward.
func (ni *NoiseInjector) StartContinuousNoise() {
	ni.wg.Add(1)
	go func() {
		defer ni.wg.Done()

		// Phase 1: Aggressive noise during first 2 seconds (inner TLS handshake window)
		deadline := time.After(2 * time.Second)
		for {
			select {
			case <-ni.stopCh:
				return
			case <-deadline:
				goto phase2
			default:
				profile := ni.engine.getProfile()
				size := randRange(profile.MinRecordPayload, 200)
				ni.sendNoise(size)
				jitterSleep(10, 50) // Every 10-50ms
			}
		}

	phase2:
		// Phase 2: Sparse background noise (every 1-5 seconds)
		for {
			interval := time.Duration(randRange(1000, 5000)) * time.Millisecond
			timer := time.NewTimer(interval)
			select {
			case <-ni.stopCh:
				timer.Stop()
				return
			case <-timer.C:
				profile := ni.engine.getProfile()
				size := randRange(profile.MinRecordPayload, 150)
				ni.sendNoise(size)
			}
		}
	}()
}

// Stop halts the continuous noise injection.
func (ni *NoiseInjector) Stop() {
	ni.mu.Lock()
	defer ni.mu.Unlock()
	if !ni.stopped {
		ni.stopped = true
		close(ni.stopCh)
		ni.wg.Wait()
	}
}

// sendNoise writes a random-filled packet of the given size.
func (ni *NoiseInjector) sendNoise(size int) error {
	if size <= 0 {
		return nil
	}
	buf := make([]byte, size)
	rand.Read(buf)
	_, err := ni.writer.Write(buf)
	return err
}

// jitterSleep sleeps for a random duration between minMs and maxMs milliseconds.
func jitterSleep(minMs, maxMs int) {
	if maxMs <= minMs {
		maxMs = minMs + 1
	}
	d := time.Duration(minMs+mathrand.Intn(maxMs-minMs)) * time.Millisecond
	time.Sleep(d)
}

// randRange returns a random int in [min, max].
func randRange(min, max int) int {
	if max <= min {
		return min
	}
	return min + mathrand.Intn(max-min+1)
}
