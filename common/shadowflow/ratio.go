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
// Traffic Ratio Balancer
//
// Real proxy traffic has a near-symmetric upload:download ratio (~1:1),
// which is a strong statistical fingerprint. Normal traffic ratios:
//   - Web browsing:  1:5 ~ 1:10  (small requests, large responses)
//   - Video streaming: 1:20 ~ 1:50 (almost all download)
//   - Cloud sync:    1:2 ~ 2:1   (varies by operation)
//
// The balancer monitors the actual upload/download byte counts and
// injects padding data into the deficit direction to maintain a
// target ratio matching the active traffic profile.
// ====================================================================

// RatioProfile defines target upload:download ratios for a profile.
type RatioProfile struct {
	// TargetUploadPct: what percentage of total traffic should be upload
	// e.g., 15 means 15% upload, 85% download → ratio ~1:5.7
	TargetUploadPct int

	// Tolerance: how far the actual ratio can deviate before padding kicks in
	// e.g., 5 means padding triggers when actual deviates by >5% from target
	TolerancePct int
}

// Per-profile ratio targets
var profileRatios = map[string]RatioProfile{
	"chrome_h2":     {TargetUploadPct: 18, TolerancePct: 5}, // browsing: ~1:5
	"safari":        {TargetUploadPct: 16, TolerancePct: 5}, // browsing: ~1:5
	"firefox":       {TargetUploadPct: 17, TolerancePct: 5}, // browsing: ~1:5
	"douyin":        {TargetUploadPct: 10, TolerancePct: 4}, // short video: ~1:9
	"bilibili":      {TargetUploadPct: 6, TolerancePct: 3},  // long video: ~1:15
	"apple_music":   {TargetUploadPct: 8, TolerancePct: 3},  // music stream: ~1:12
	"taobao":        {TargetUploadPct: 20, TolerancePct: 5}, // shopping: ~1:4
	"icloud_sync":   {TargetUploadPct: 40, TolerancePct: 8}, // sync: ~1:1.5 (upload heavy)
	"tencent_video": {TargetUploadPct: 4, TolerancePct: 2},  // video: ~1:24
}

// GetRatioProfile returns the ratio profile for a traffic profile name.
func GetRatioProfile(name string) RatioProfile {
	if r, ok := profileRatios[name]; ok {
		return r
	}
	// Default: generic browsing ratio
	return RatioProfile{TargetUploadPct: 18, TolerancePct: 5}
}

// RatioBalancer monitors and adjusts the upload/download traffic ratio.
type RatioBalancer struct {
	writer io.Writer // downstream writer (to client)
	engine *CamouflageEngine

	// Byte counters
	uploadBytes   atomic.Int64
	downloadBytes atomic.Int64

	// Control
	stopCh  chan struct{}
	stopped atomic.Bool
	wg      sync.WaitGroup
}

// NewRatioBalancer creates a ratio balancer that injects download padding.
func NewRatioBalancer(writer io.Writer, engine *CamouflageEngine) *RatioBalancer {
	rb := &RatioBalancer{
		writer: writer,
		engine: engine,
		stopCh: make(chan struct{}),
	}
	rb.wg.Add(1)
	go rb.balanceLoop()

	log.Info("ShadowFlow: traffic ratio balancer started")
	return rb
}

// RecordUpload records bytes sent from client to server.
func (rb *RatioBalancer) RecordUpload(n int) {
	rb.uploadBytes.Add(int64(n))
}

// RecordDownload records bytes sent from server to client.
func (rb *RatioBalancer) RecordDownload(n int) {
	rb.downloadBytes.Add(int64(n))
}

// Close stops the balancer.
func (rb *RatioBalancer) Close() {
	if rb.stopped.CompareAndSwap(false, true) {
		close(rb.stopCh)
		rb.wg.Wait()
	}
}

// balanceLoop periodically checks the ratio and injects padding.
func (rb *RatioBalancer) balanceLoop() {
	defer rb.wg.Done()

	// Check every 5-10 seconds (randomized to avoid patterns)
	for {
		interval := time.Duration(5000+mathrand.Intn(5000)) * time.Millisecond
		timer := time.NewTimer(interval)
		select {
		case <-rb.stopCh:
			timer.Stop()
			return
		case <-timer.C:
			rb.balance()
		}
	}
}

func (rb *RatioBalancer) balance() {
	up := rb.uploadBytes.Load()
	down := rb.downloadBytes.Load()
	total := up + down

	// Need at least 50KB of traffic before ratio adjustment kicks in
	if total < 50*1024 {
		return
	}

	profile := rb.engine.getProfile()
	ratio := GetRatioProfile(profile.Name)

	// Calculate actual upload percentage
	actualUpPct := int(up * 100 / total)
	targetUpPct := ratio.TargetUploadPct

	// Check if we need to inject padding
	diff := actualUpPct - targetUpPct

	if diff > ratio.TolerancePct {
		// Upload percentage too high → need more download padding
		// Calculate how many bytes of download padding to inject
		// Target: up / (down + padding) = targetUpPct / 100
		// So: padding = (up * 100 / targetUpPct) - total
		targetTotal := up * 100 / int64(targetUpPct)
		paddingNeeded := targetTotal - total
		if paddingNeeded > 0 {
			// Cap at 64KB per injection to avoid bursts
			if paddingNeeded > 64*1024 {
				paddingNeeded = 64 * 1024
			}
			rb.injectDownloadPadding(int(paddingNeeded))
			log.WithFields(log.Fields{
				"profile":   profile.Name,
				"actual_up": actualUpPct,
				"target_up": targetUpPct,
				"injected":  paddingNeeded,
			}).Debug("ShadowFlow: ratio balancer injected download padding")
		}
	}
	// Note: if download is too high relative to upload, we don't pad upload
	// because that would increase bandwidth usage significantly.
	// A download-heavy ratio is normal and not suspicious.
}

// injectDownloadPadding sends random padding data to the client.
// The padding is shaped to match the current profile's size distribution.
func (rb *RatioBalancer) injectDownloadPadding(totalBytes int) {
	profile := rb.engine.getProfile()
	remaining := totalBytes

	for remaining > 0 {
		// Use profile's S2C size distribution for realistic chunk sizes
		chunkSize := SampleSize(profile.S2CSizes)
		if chunkSize > remaining {
			chunkSize = remaining
		}
		if chunkSize < profile.MinRecordPayload {
			chunkSize = profile.MinRecordPayload
		}

		padding := make([]byte, chunkSize)
		rand.Read(padding)

		_, err := rb.writer.Write(padding)
		if err != nil {
			return // connection probably closed
		}

		remaining -= chunkSize
		rb.downloadBytes.Add(int64(chunkSize))

		// Timing jitter between padding chunks
		if profile.InterPacketDelayMax > 0 {
			delay := profile.InterPacketDelayMin
			if profile.InterPacketDelayMax > profile.InterPacketDelayMin {
				delay += mathrand.Intn(profile.InterPacketDelayMax - profile.InterPacketDelayMin)
			}
			if delay > 0 {
				time.Sleep(time.Duration(delay) * time.Microsecond)
			}
		}
	}
}
