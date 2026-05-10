package shadowflow

import (
	mathrand "math/rand"
	"sync"
)

// ====================================================================
// Client Fingerprint Diversifier
//
// Each user connection gets a randomized "client identity" combining:
//   - Traffic profile (Chrome/Safari/Firefox)
//   - Preferred SNI from the pool
//   - Behavioral traits (request timing, keep-alive patterns)
//
// This prevents GFW from building a consistent "user fingerprint"
// across multiple connections from the same source.
//
// Without diversification:
//   Conn1: Chrome profile + apple.com SNI
//   Conn2: Chrome profile + apple.com SNI  ← same pattern → detectable
//   Conn3: Chrome profile + apple.com SNI
//
// With diversification:
//   Conn1: Chrome profile + apple.com SNI + aggressive keep-alive
//   Conn2: Firefox profile + microsoft.com SNI + lazy keep-alive
//   Conn3: Safari profile + cloudflare.com SNI + no keep-alive
//   ↑ Each connection looks like a different client
// ====================================================================

// ClientIdentity represents a randomized client persona for one connection.
type ClientIdentity struct {
	// ProfileName determines packet size distribution
	ProfileName string

	// SNI to use for this connection (selected from pool)
	SNI string

	// KeepAliveStyle affects connection behavior timing
	KeepAliveStyle KeepAliveStyle

	// InitialBurstSize: how many packets to send in the initial burst
	// (mimics different browser connection strategies)
	InitialBurstSize int

	// IdleNoiseLevel: 0=none, 1=light, 2=moderate, 3=aggressive
	IdleNoiseLevel int
}

// KeepAliveStyle defines different connection maintenance patterns.
type KeepAliveStyle int

const (
	KeepAliveAggressive KeepAliveStyle = iota // Send pings every 5-10s (Chrome-like)
	KeepAliveModerate                         // Send pings every 15-30s (Firefox-like)
	KeepAliveLazy                             // Send pings every 30-60s (Safari-like)
	KeepAliveNone                             // No explicit keep-alive
)

// Diversifier generates randomized client identities.
type Diversifier struct {
	sniPool    []string
	profiles   []string
	mu         sync.RWMutex
}

// NewDiversifier creates a fingerprint diversifier.
func NewDiversifier(sniPool []string) *Diversifier {
	profiles := []string{"chrome_h2", "safari", "firefox"}

	if len(sniPool) == 0 {
		sniPool = []string{
			"www.apple.com",
			"www.microsoft.com",
			"cdn.cloudflare.com",
			"www.google.com",
			"ajax.googleapis.com",
		}
	}

	return &Diversifier{
		sniPool:  sniPool,
		profiles: profiles,
	}
}

// Generate creates a new randomized client identity.
// Each call produces a different combination.
func (d *Diversifier) Generate() *ClientIdentity {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return &ClientIdentity{
		ProfileName:      d.profiles[mathrand.Intn(len(d.profiles))],
		SNI:              d.sniPool[mathrand.Intn(len(d.sniPool))],
		KeepAliveStyle:   KeepAliveStyle(mathrand.Intn(4)),
		InitialBurstSize: 3 + mathrand.Intn(4), // 3-6 initial packets
		IdleNoiseLevel:   mathrand.Intn(4),      // 0-3
	}
}

// GenerateForProfile creates an identity with a specific profile but random other traits.
func (d *Diversifier) GenerateForProfile(profileName string) *ClientIdentity {
	id := d.Generate()
	id.ProfileName = profileName
	return id
}

// UpdateSNIPool updates the available SNI pool.
func (d *Diversifier) UpdateSNIPool(sniPool []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(sniPool) > 0 {
		d.sniPool = sniPool
	}
}

// ApplyIdentity configures a CamouflageEngine with the given identity.
func ApplyIdentity(engine *CamouflageEngine, identity *ClientIdentity) {
	// Set the traffic profile
	profile := GetProfile(identity.ProfileName)
	engine.activeProfile.Store(profile)

	// Adjust engine behavior based on identity traits
	engine.mu.Lock()
	defer engine.mu.Unlock()

	// Reset packet counters for fresh initial sequence
	engine.c2sPacketIndex = 0
	engine.s2cPacketIndex = 0
}

// GetKeepAliveInterval returns the keep-alive interval for the given style.
func (id *ClientIdentity) GetKeepAliveInterval() (min, max int) {
	switch id.KeepAliveStyle {
	case KeepAliveAggressive:
		return 5, 10
	case KeepAliveModerate:
		return 15, 30
	case KeepAliveLazy:
		return 30, 60
	case KeepAliveNone:
		return 0, 0
	default:
		return 15, 30
	}
}
