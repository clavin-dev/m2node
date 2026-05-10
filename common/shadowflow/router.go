package shadowflow

import (
	mathrand "math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

// ====================================================================
// CDN Multi-Domain Router
//
// When proxying through CDN, rotates between multiple domains for
// upload and download traffic. This disperses traffic across domains
// so GFW sees the user visiting many different websites instead of
// maintaining a long connection to a single suspicious domain.
//
// Architecture:
//   Client → [TLS to up1.abc.com] → CDN → Origin Server (upload)
//   Client → [TLS to dl2.xyz.com] → CDN → Origin Server (download)
//   
//   Next request:
//   Client → [TLS to up3.def.com] → CDN → Origin Server (upload)
//   Client → [TLS to dl1.uvw.com] → CDN → Origin Server (download)
//
// All domains resolve to CDN IPs and route to the same origin.
// ====================================================================

// DomainRouter manages multi-domain rotation for CDN traffic.
type DomainRouter struct {
	uploadDomains   []string
	downloadDomains []string
	mu              sync.RWMutex

	// Rotation strategy
	strategy RotationStrategy

	// Per-domain tracking for weighted rotation
	uploadIdx   atomic.Uint32
	downloadIdx atomic.Uint32

	// Domain health tracking
	domainHealth sync.Map // map[string]*domainStatus

	// Switch interval for time-based rotation
	switchInterval time.Duration
	lastSwitch     atomic.Value // time.Time
}

// RotationStrategy defines how domains are selected.
type RotationStrategy int

const (
	// RotateRandom picks a random domain each time
	RotateRandom RotationStrategy = iota

	// RotateRoundRobin cycles through domains sequentially
	RotateRoundRobin

	// RotateTimeBased switches domain every N seconds
	RotateTimeBased

	// RotatePerConnection uses a different domain for each new connection
	RotatePerConnection
)

type domainStatus struct {
	failures  atomic.Int32
	lastCheck atomic.Value // time.Time
	healthy   atomic.Bool
}

// DomainRouterConfig configures the domain router.
type DomainRouterConfig struct {
	// Domains as newline-separated strings (from panel TextArea)
	UploadHosts   string
	DownloadHosts string

	// Rotation strategy (default: Random)
	Strategy RotationStrategy

	// For TimeBased strategy: interval in seconds
	SwitchIntervalSec int
}

// NewDomainRouter creates a domain router from panel config.
func NewDomainRouter(config *DomainRouterConfig) *DomainRouter {
	upload := parseDomainList(config.UploadHosts)
	download := parseDomainList(config.DownloadHosts)

	if len(upload) == 0 {
		upload = []string{""}
	}
	if len(download) == 0 {
		download = []string{""}
	}

	interval := time.Duration(config.SwitchIntervalSec) * time.Second
	if interval <= 0 {
		interval = 30 * time.Second
	}

	dr := &DomainRouter{
		uploadDomains:   upload,
		downloadDomains: download,
		strategy:        config.Strategy,
		switchInterval:  interval,
	}
	dr.lastSwitch.Store(time.Now())

	// Initialize health for all domains
	for _, d := range upload {
		status := &domainStatus{}
		status.healthy.Store(true)
		dr.domainHealth.Store(d, status)
	}
	for _, d := range download {
		status := &domainStatus{}
		status.healthy.Store(true)
		dr.domainHealth.Store(d, status)
	}

	log.WithFields(log.Fields{
		"upload_domains":   len(upload),
		"download_domains": len(download),
		"strategy":         config.Strategy,
	}).Info("ShadowFlow: domain router initialized")

	return dr
}

// GetUploadDomain returns the next upload domain to use.
func (dr *DomainRouter) GetUploadDomain() string {
	return dr.pickDomain(dr.uploadDomains, &dr.uploadIdx)
}

// GetDownloadDomain returns the next download domain to use.
func (dr *DomainRouter) GetDownloadDomain() string {
	return dr.pickDomain(dr.downloadDomains, &dr.downloadIdx)
}

// pickDomain selects a domain based on the rotation strategy.
func (dr *DomainRouter) pickDomain(domains []string, idx *atomic.Uint32) string {
	dr.mu.RLock()
	defer dr.mu.RUnlock()

	if len(domains) == 0 {
		return ""
	}
	if len(domains) == 1 {
		return domains[0]
	}

	// Filter healthy domains
	healthy := dr.filterHealthy(domains)
	if len(healthy) == 0 {
		healthy = domains // fallback to all if none healthy
	}

	switch dr.strategy {
	case RotateRandom:
		return healthy[mathrand.Intn(len(healthy))]

	case RotateRoundRobin:
		i := idx.Add(1) - 1
		return healthy[int(i)%len(healthy)]

	case RotateTimeBased:
		last, _ := dr.lastSwitch.Load().(time.Time)
		elapsed := time.Since(last)
		slot := int(elapsed / dr.switchInterval)
		return healthy[slot%len(healthy)]

	case RotatePerConnection:
		return healthy[mathrand.Intn(len(healthy))]

	default:
		return healthy[mathrand.Intn(len(healthy))]
	}
}

// filterHealthy returns only healthy domains.
func (dr *DomainRouter) filterHealthy(domains []string) []string {
	healthy := make([]string, 0, len(domains))
	for _, d := range domains {
		if v, ok := dr.domainHealth.Load(d); ok {
			status := v.(*domainStatus)
			if status.healthy.Load() {
				healthy = append(healthy, d)
			}
		} else {
			healthy = append(healthy, d)
		}
	}
	return healthy
}

// ReportFailure marks a domain as potentially unhealthy.
// After 3 consecutive failures, the domain is marked unhealthy.
// It auto-recovers after 5 minutes.
func (dr *DomainRouter) ReportFailure(domain string) {
	if v, ok := dr.domainHealth.Load(domain); ok {
		status := v.(*domainStatus)
		failures := status.failures.Add(1)
		if failures >= 3 {
			status.healthy.Store(false)
			log.WithField("domain", domain).Warn("ShadowFlow: domain marked unhealthy")

			// Schedule auto-recovery
			go func() {
				time.Sleep(5 * time.Minute)
				status.failures.Store(0)
				status.healthy.Store(true)
				log.WithField("domain", domain).Info("ShadowFlow: domain recovered")
			}()
		}
	}
}

// ReportSuccess resets the failure counter for a domain.
func (dr *DomainRouter) ReportSuccess(domain string) {
	if v, ok := dr.domainHealth.Load(domain); ok {
		status := v.(*domainStatus)
		status.failures.Store(0)
		status.healthy.Store(true)
	}
}

// UpdateDomains hot-reloads the domain lists (from panel config update).
func (dr *DomainRouter) UpdateDomains(uploadHosts, downloadHosts string) {
	dr.mu.Lock()
	defer dr.mu.Unlock()

	upload := parseDomainList(uploadHosts)
	download := parseDomainList(downloadHosts)

	if len(upload) > 0 {
		dr.uploadDomains = upload
	}
	if len(download) > 0 {
		dr.downloadDomains = download
	}

	log.WithFields(log.Fields{
		"upload_domains":   len(dr.uploadDomains),
		"download_domains": len(dr.downloadDomains),
	}).Info("ShadowFlow: domain lists updated")
}

// GetStats returns domain router statistics.
func (dr *DomainRouter) GetStats() map[string]interface{} {
	dr.mu.RLock()
	defer dr.mu.RUnlock()

	stats := map[string]interface{}{
		"upload_count":   len(dr.uploadDomains),
		"download_count": len(dr.downloadDomains),
		"strategy":       dr.strategy,
	}

	healthMap := make(map[string]bool)
	dr.domainHealth.Range(func(key, value any) bool {
		domain := key.(string)
		status := value.(*domainStatus)
		healthMap[domain] = status.healthy.Load()
		return true
	})
	stats["health"] = healthMap

	return stats
}

// parseDomainList splits newline/comma-separated domains and trims whitespace.
func parseDomainList(raw string) []string {
	if raw == "" {
		return nil
	}

	// Support both newline and comma separators
	raw = strings.ReplaceAll(raw, ",", "\n")
	lines := strings.Split(raw, "\n")

	var result []string
	for _, line := range lines {
		domain := strings.TrimSpace(line)
		if domain != "" {
			result = append(result, domain)
		}
	}
	return result
}
