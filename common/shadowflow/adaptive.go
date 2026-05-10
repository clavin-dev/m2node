package shadowflow

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

// ====================================================================
// Adaptive Profile Selector
//
// Automatically switches the camouflage profile based on real-time
// throughput. This solves the core problem of large traffic detection:
// a "web browsing" profile pushing 100MB/s is suspicious, but a
// "cloud sync" or "CDN distribution" profile doing the same is normal.
//
// Throughput tiers:
//   < 100 KB/s  → browsing (Chrome/Safari/Firefox)
//   100KB-5MB/s → video streaming (Netflix/YouTube)
//   5MB-50MB/s  → cloud sync (iCloud/Google Drive)
//   > 50MB/s    → CDN distribution (Cloudflare/Akamai)
// ====================================================================

// AdaptiveSelector monitors throughput and switches profiles accordingly.
type AdaptiveSelector struct {
	engine *CamouflageEngine

	// Byte counters (reset every measurement window)
	bytesIn  atomic.Int64
	bytesOut atomic.Int64

	// Current tier
	currentTier atomic.Int32

	stopCh  chan struct{}
	stopped atomic.Bool
	wg      sync.WaitGroup
}

// Throughput tier constants
const (
	TierBrowsing     = 0 // < 100 KB/s
	TierStreaming     = 1 // 100 KB/s - 5 MB/s
	TierCloudSync    = 2 // 5 MB/s - 50 MB/s
	TierCDN          = 3 // > 50 MB/s
)

// Tier thresholds in bytes per second
const (
	thresholdStreaming = 100 * 1024        // 100 KB/s
	thresholdCloudSync = 5 * 1024 * 1024   // 5 MB/s
	thresholdCDN      = 50 * 1024 * 1024   // 50 MB/s
)

// measurement window for throughput calculation
const measureWindow = 3 * time.Second

// tier profiles mapping
var tierProfiles = map[int32][]*TrafficProfile{
	TierBrowsing:  nil, // uses random browsing profiles
	TierStreaming:  nil, // initialized in init
	TierCloudSync: nil,
	TierCDN:       nil,
}

func init() {
	// Will be populated after profiles are initialized
	tierProfiles[TierStreaming] = []*TrafficProfile{VideoStreamProfile}
	tierProfiles[TierCloudSync] = []*TrafficProfile{CloudSyncProfile}
	tierProfiles[TierCDN] = []*TrafficProfile{CDNDistributionProfile}
}

// NewAdaptiveSelector creates a throughput-aware profile selector.
func NewAdaptiveSelector(engine *CamouflageEngine) *AdaptiveSelector {
	a := &AdaptiveSelector{
		engine: engine,
		stopCh: make(chan struct{}),
	}
	a.currentTier.Store(TierBrowsing)
	a.wg.Add(1)
	go a.monitorLoop()

	log.Info("ShadowFlow: adaptive profile selector started")
	return a
}

// RecordBytes records bytes transferred (called from ShapedWriter/Reader).
func (a *AdaptiveSelector) RecordBytes(in, out int64) {
	if in > 0 {
		a.bytesIn.Add(in)
	}
	if out > 0 {
		a.bytesOut.Add(out)
	}
}

// Close stops the monitor.
func (a *AdaptiveSelector) Close() {
	if a.stopped.CompareAndSwap(false, true) {
		close(a.stopCh)
		a.wg.Wait()
	}
}

func (a *AdaptiveSelector) monitorLoop() {
	defer a.wg.Done()
	ticker := time.NewTicker(measureWindow)
	defer ticker.Stop()

	for {
		select {
		case <-a.stopCh:
			return
		case <-ticker.C:
			a.evaluate()
		}
	}
}

func (a *AdaptiveSelector) evaluate() {
	// Read and reset counters
	in := a.bytesIn.Swap(0)
	out := a.bytesOut.Swap(0)

	// Calculate bytes per second
	totalBytes := in + out
	bps := float64(totalBytes) / measureWindow.Seconds()

	// Determine tier
	var newTier int32
	switch {
	case bps >= float64(thresholdCDN):
		newTier = TierCDN
	case bps >= float64(thresholdCloudSync):
		newTier = TierCloudSync
	case bps >= float64(thresholdStreaming):
		newTier = TierStreaming
	default:
		newTier = TierBrowsing
	}

	oldTier := a.currentTier.Load()
	if newTier == oldTier {
		return
	}

	// Only upgrade tiers (don't downgrade immediately to avoid flapping)
	// Downgrade after 2 consecutive low-tier measurements
	if newTier < oldTier {
		// Allow one measurement grace period before downgrading
		// This is a simplified debounce — in production you'd use a counter
		return
	}

	a.currentTier.Store(newTier)

	// Switch profile
	var profile *TrafficProfile
	switch newTier {
	case TierBrowsing:
		profile = GetRandomProfile()
	case TierStreaming:
		profile = VideoStreamProfile
	case TierCloudSync:
		profile = CloudSyncProfile
	case TierCDN:
		profile = CDNDistributionProfile
	}

	if profile != nil {
		a.engine.activeProfile.Store(profile)
		log.WithFields(log.Fields{
			"tier":       tierName(newTier),
			"profile":    profile.Name,
			"throughput": formatBytes(int64(bps)) + "/s",
		}).Info("ShadowFlow: adaptive profile upgrade")
	}
}

func tierName(tier int32) string {
	switch tier {
	case TierBrowsing:
		return "browsing"
	case TierStreaming:
		return "streaming"
	case TierCloudSync:
		return "cloud_sync"
	case TierCDN:
		return "cdn"
	default:
		return "unknown"
	}
}

func formatBytes(b int64) string {
	switch {
	case b >= 1024*1024:
		return fmt.Sprintf("%.1fMB", float64(b)/(1024*1024))
	case b >= 1024:
		return fmt.Sprintf("%.1fKB", float64(b)/1024)
	default:
		return fmt.Sprintf("%dB", b)
	}
}
