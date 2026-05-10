// Package shadowflow implements the TLS Record Size camouflage engine
// and ShadowStream transport protocol for the ShadowFlow proxy.
//
// The camouflage engine reshapes TLS record sizes to match real browser
// traffic distributions, eliminating statistical fingerprints that GFW
// uses for detection (e.g., the "19-byte" Vision signature).
//
// ShadowStream is a custom multiplexed transport that sits inside TLS
// and produces zero protocol-level fingerprints.
package shadowflow

import (
	"math/rand"
	"sync"
)

// ====================================================================
// Traffic Profiles — sampled from real browser captures
// ====================================================================

// SizeRange defines a weighted range for TLS record payload sizes.
// Weight controls how often this range is selected during sampling.
type SizeRange struct {
	Min    int // minimum TLS record payload size (bytes)
	Max    int // maximum TLS record payload size (bytes)
	Weight int // selection weight (higher = more frequent)
}

// InitialPacket defines a specific packet in the handshake sequence.
type InitialPacket struct {
	MinSize int // minimum size for this position
	MaxSize int // maximum size for this position
}

// TrafficProfile models real-world TLS traffic characteristics.
// Profiles are built from actual pcap data of real browsers.
type TrafficProfile struct {
	Name string

	// C2S / S2C packet size distributions (after initial phase)
	C2SSizes []SizeRange
	S2CSizes []SizeRange

	// Initial handshake sequence (first N packets after TLS handshake)
	// These are critical — VLESS+Vision was caught primarily here
	C2SInitial []InitialPacket
	S2CInitial []InitialPacket

	// Minimum payload size for any record (eliminates "19-byte" fingerprint)
	MinRecordPayload int

	// Maximum TLS record payload size (RFC 8449: max 16384)
	MaxRecordPayload int
}

// Pre-built profiles from real pcap analysis
var (
	// ChromeH2Profile — Chrome 120+ browsing Google services over HTTP/2
	// Captured from: Chrome → google.com, youtube.com, gmail.com
	// Key characteristics:
	//   - Large Client Hello (~1700 bytes)
	//   - Varied C→S sizes (HEADERS, DATA, WINDOW_UPDATE frames)
	//   - S→C dominated by large data frames (14000-16384)
	//   - Minimum observed record: 26 bytes (WINDOW_UPDATE)
	ChromeH2Profile = &TrafficProfile{
		Name: "chrome_h2",
		C2SSizes: []SizeRange{
			{Min: 26, Max: 120, Weight: 25},    // WINDOW_UPDATE, PING, small HEADERS
			{Min: 121, Max: 500, Weight: 30},    // Medium HEADERS, small DATA
			{Min: 501, Max: 1200, Weight: 25},   // Larger HEADERS with cookies
			{Min: 1201, Max: 4000, Weight: 12},  // POST bodies, large requests
			{Min: 4001, Max: 16384, Weight: 8},  // File uploads, large payloads
		},
		S2CSizes: []SizeRange{
			{Min: 26, Max: 100, Weight: 10},     // SETTINGS_ACK, PING_ACK, WINDOW_UPDATE
			{Min: 101, Max: 500, Weight: 15},    // Small responses, HEADERS
			{Min: 501, Max: 2000, Weight: 15},   // Medium responses, JSON APIs
			{Min: 2001, Max: 8000, Weight: 20},  // Larger responses, HTML pages
			{Min: 8001, Max: 14000, Weight: 20}, // Large data, images
			{Min: 14001, Max: 16384, Weight: 20},// Maximum TLS records (common for streaming)
		},
		// Chrome H2 initial sequence after TLS handshake:
		// 1. HTTP/2 connection preface + SETTINGS (magic + settings frame)
		// 2. WINDOW_UPDATE (connection-level)
		// 3. HEADERS (first request)
		// 4. DATA (if POST) or nothing
		C2SInitial: []InitialPacket{
			{MinSize: 60, MaxSize: 120},   // H2 SETTINGS frame
			{MinSize: 26, MaxSize: 50},    // WINDOW_UPDATE
			{MinSize: 150, MaxSize: 800},  // HEADERS (first GET request)
			{MinSize: 26, MaxSize: 100},   // WINDOW_UPDATE / PRIORITY
		},
		// Server response initial sequence:
		// 1. SETTINGS + SETTINGS_ACK
		// 2. WINDOW_UPDATE
		// 3. HEADERS (response headers)
		// 4. DATA (response body, usually large)
		S2CInitial: []InitialPacket{
			{MinSize: 80, MaxSize: 200},     // SETTINGS
			{MinSize: 26, MaxSize: 50},      // WINDOW_UPDATE
			{MinSize: 100, MaxSize: 600},    // HEADERS (response)
			{MinSize: 2000, MaxSize: 16384}, // DATA (first chunk, usually large)
		},
		MinRecordPayload: 26,    // Never produce records smaller than this
		MaxRecordPayload: 16384, // TLS maximum
	}

	// SafariProfile — Safari on macOS/iOS browsing Apple services
	// Key: larger initial packets, different size distribution
	SafariProfile = &TrafficProfile{
		Name: "safari",
		C2SSizes: []SizeRange{
			{Min: 30, Max: 150, Weight: 20},
			{Min: 151, Max: 600, Weight: 30},
			{Min: 601, Max: 1500, Weight: 25},
			{Min: 1501, Max: 5000, Weight: 15},
			{Min: 5001, Max: 16384, Weight: 10},
		},
		S2CSizes: []SizeRange{
			{Min: 30, Max: 200, Weight: 10},
			{Min: 201, Max: 1000, Weight: 15},
			{Min: 1001, Max: 4000, Weight: 20},
			{Min: 4001, Max: 10000, Weight: 25},
			{Min: 10001, Max: 16384, Weight: 30},
		},
		C2SInitial: []InitialPacket{
			{MinSize: 80, MaxSize: 200},
			{MinSize: 30, MaxSize: 60},
			{MinSize: 200, MaxSize: 1000},
			{MinSize: 30, MaxSize: 120},
		},
		S2CInitial: []InitialPacket{
			{MinSize: 100, MaxSize: 300},
			{MinSize: 30, MaxSize: 60},
			{MinSize: 150, MaxSize: 800},
			{MinSize: 3000, MaxSize: 16384},
		},
		MinRecordPayload: 30,
		MaxRecordPayload: 16384,
	}

	// FirefoxProfile — Firefox browsing general websites
	FirefoxProfile = &TrafficProfile{
		Name: "firefox",
		C2SSizes: []SizeRange{
			{Min: 28, Max: 100, Weight: 20},
			{Min: 101, Max: 450, Weight: 30},
			{Min: 451, Max: 1100, Weight: 25},
			{Min: 1101, Max: 3500, Weight: 15},
			{Min: 3501, Max: 16384, Weight: 10},
		},
		S2CSizes: []SizeRange{
			{Min: 28, Max: 150, Weight: 10},
			{Min: 151, Max: 800, Weight: 15},
			{Min: 801, Max: 3000, Weight: 20},
			{Min: 3001, Max: 10000, Weight: 25},
			{Min: 10001, Max: 16384, Weight: 30},
		},
		C2SInitial: []InitialPacket{
			{MinSize: 70, MaxSize: 150},
			{MinSize: 28, MaxSize: 55},
			{MinSize: 180, MaxSize: 750},
			{MinSize: 28, MaxSize: 90},
		},
		S2CInitial: []InitialPacket{
			{MinSize: 90, MaxSize: 250},
			{MinSize: 28, MaxSize: 55},
			{MinSize: 120, MaxSize: 700},
			{MinSize: 2500, MaxSize: 16384},
		},
		MinRecordPayload: 28,
		MaxRecordPayload: 16384,
	}

	// ================================================================
	// HIGH-BANDWIDTH PROFILES — for large traffic camouflage
	// ================================================================

	// VideoStreamProfile — Netflix/YouTube adaptive streaming over HTTP/2
	// Captured from: Chrome → youtube.com 4K streaming, netflix.com
	// Key characteristics:
	//   - S→C: predominantly large chunks (video segments)
	//   - Periodic small packets (heartbeat, buffer status)
	//   - C→S: small requests (range requests, quality reports)
	//   - Burst pattern: large chunk → small pause → large chunk
	VideoStreamProfile = &TrafficProfile{
		Name: "video_stream",
		C2SSizes: []SizeRange{
			{Min: 26, Max: 80, Weight: 35},     // Range requests, ACK, heartbeat
			{Min: 81, Max: 300, Weight: 30},     // Quality change requests, analytics
			{Min: 301, Max: 800, Weight: 20},    // Buffering status, DRM license
			{Min: 801, Max: 2000, Weight: 10},   // Subtitle fetch, manifest update
			{Min: 2001, Max: 5000, Weight: 5},   // Upload (watch history, telemetry)
		},
		S2CSizes: []SizeRange{
			{Min: 26, Max: 100, Weight: 5},       // ACK, SETTINGS, WINDOW_UPDATE
			{Min: 101, Max: 500, Weight: 5},      // HEADERS, small metadata
			{Min: 501, Max: 4000, Weight: 5},     // Manifests, playlists (m3u8/mpd)
			{Min: 4001, Max: 12000, Weight: 15},  // Medium video chunks
			{Min: 12001, Max: 16384, Weight: 70}, // ★ Large video data (dominant)
		},
		C2SInitial: []InitialPacket{
			{MinSize: 60, MaxSize: 120},  // H2 SETTINGS
			{MinSize: 26, MaxSize: 50},   // WINDOW_UPDATE
			{MinSize: 200, MaxSize: 600}, // First video manifest request
			{MinSize: 26, MaxSize: 80},   // ACK
		},
		S2CInitial: []InitialPacket{
			{MinSize: 80, MaxSize: 200},     // SETTINGS
			{MinSize: 26, MaxSize: 50},      // WINDOW_UPDATE
			{MinSize: 500, MaxSize: 3000},   // Manifest response
			{MinSize: 12000, MaxSize: 16384}, // First video segment (big)
		},
		MinRecordPayload: 26,
		MaxRecordPayload: 16384,
	}

	// CloudSyncProfile — iCloud/Google Drive/OneDrive sync
	// Captured from: macOS iCloud sync, Google Drive large upload
	// Key characteristics:
	//   - Bidirectional large chunks (upload AND download)
	//   - Periodic metadata exchanges (file lists, checksums)
	//   - Very large sustained throughput is NORMAL for this profile
	//   - Mix of small control + large data is expected
	CloudSyncProfile = &TrafficProfile{
		Name: "cloud_sync",
		C2SSizes: []SizeRange{
			{Min: 30, Max: 100, Weight: 10},     // Keepalive, ACK
			{Min: 101, Max: 500, Weight: 10},    // Metadata, file info
			{Min: 501, Max: 4000, Weight: 15},   // Small file uploads, checksums
			{Min: 4001, Max: 12000, Weight: 25}, // Medium file chunks
			{Min: 12001, Max: 16384, Weight: 40}, // ★ Large upload chunks (dominant)
		},
		S2CSizes: []SizeRange{
			{Min: 30, Max: 100, Weight: 8},       // ACK, control
			{Min: 101, Max: 500, Weight: 7},      // Metadata responses
			{Min: 501, Max: 4000, Weight: 10},    // File list, delta info
			{Min: 4001, Max: 12000, Weight: 25},  // Medium download chunks
			{Min: 12001, Max: 16384, Weight: 50}, // ★ Large download chunks (dominant)
		},
		C2SInitial: []InitialPacket{
			{MinSize: 60, MaxSize: 150},    // TLS setup
			{MinSize: 30, MaxSize: 60},     // Control
			{MinSize: 300, MaxSize: 1200},  // Auth + sync state
			{MinSize: 100, MaxSize: 500},   // File list request
		},
		S2CInitial: []InitialPacket{
			{MinSize: 80, MaxSize: 250},
			{MinSize: 30, MaxSize: 60},
			{MinSize: 200, MaxSize: 800},
			{MinSize: 4000, MaxSize: 16384},
		},
		MinRecordPayload: 30,
		MaxRecordPayload: 16384,
	}

	// CDNDistributionProfile — Cloudflare/Akamai CDN edge distribution
	// Key: Mostly S→C, very large records, minimal C→S
	// This profile justifies the highest possible sustained throughput
	CDNDistributionProfile = &TrafficProfile{
		Name: "cdn_distribution",
		C2SSizes: []SizeRange{
			{Min: 26, Max: 60, Weight: 50},      // Range requests, tiny
			{Min: 61, Max: 300, Weight: 30},      // HEADERS, small requests
			{Min: 301, Max: 1000, Weight: 15},    // Occasional POST
			{Min: 1001, Max: 4000, Weight: 5},    // Rare large C→S
		},
		S2CSizes: []SizeRange{
			{Min: 26, Max: 100, Weight: 3},        // ACK only
			{Min: 101, Max: 1000, Weight: 2},      // Headers
			{Min: 1001, Max: 8000, Weight: 5},     // Small assets
			{Min: 8001, Max: 14000, Weight: 10},   // Medium assets
			{Min: 14001, Max: 16384, Weight: 80},  // ★★ Massive data (CDN bulk)
		},
		C2SInitial: []InitialPacket{
			{MinSize: 60, MaxSize: 100},
			{MinSize: 26, MaxSize: 40},
			{MinSize: 100, MaxSize: 400},
		},
		S2CInitial: []InitialPacket{
			{MinSize: 80, MaxSize: 200},
			{MinSize: 26, MaxSize: 40},
			{MinSize: 14000, MaxSize: 16384}, // CDN immediately sends large data
		},
		MinRecordPayload: 26,
		MaxRecordPayload: 16384,
	}

	// profileRegistry for lookup by name
	profileRegistry = map[string]*TrafficProfile{
		"chrome_h2":        ChromeH2Profile,
		"safari":           SafariProfile,
		"firefox":          FirefoxProfile,
		"video_stream":     VideoStreamProfile,
		"cloud_sync":       CloudSyncProfile,
		"cdn_distribution": CDNDistributionProfile,
	}
	registryMu sync.RWMutex
)

// GetProfile returns a profile by name, defaulting to ChromeH2.
func GetProfile(name string) *TrafficProfile {
	registryMu.RLock()
	defer registryMu.RUnlock()
	if p, ok := profileRegistry[name]; ok {
		return p
	}
	return ChromeH2Profile
}

// GetRandomProfile returns a randomly selected profile.
func GetRandomProfile() *TrafficProfile {
	registryMu.RLock()
	defer registryMu.RUnlock()
	profiles := make([]*TrafficProfile, 0, len(profileRegistry))
	for _, p := range profileRegistry {
		profiles = append(profiles, p)
	}
	return profiles[rand.Intn(len(profiles))]
}

// SampleSize picks a random size from the given distribution.
func SampleSize(ranges []SizeRange) int {
	totalWeight := 0
	for _, r := range ranges {
		totalWeight += r.Weight
	}
	if totalWeight == 0 {
		return 512
	}
	pick := rand.Intn(totalWeight)
	cumulative := 0
	for _, r := range ranges {
		cumulative += r.Weight
		if pick < cumulative {
			if r.Min == r.Max {
				return r.Min
			}
			return r.Min + rand.Intn(r.Max-r.Min+1)
		}
	}
	// fallback
	last := ranges[len(ranges)-1]
	return last.Min + rand.Intn(last.Max-last.Min+1)
}

// SampleInitialSize picks a size for a specific position in the initial sequence.
func SampleInitialSize(initial []InitialPacket, index int) int {
	if index >= len(initial) {
		return -1 // no more initial packets, use normal distribution
	}
	p := initial[index]
	if p.MinSize == p.MaxSize {
		return p.MinSize
	}
	return p.MinSize + rand.Intn(p.MaxSize-p.MinSize+1)
}
