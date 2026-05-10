package shadowflow

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"sync"
)

// ====================================================================
// Traffic Profile Collector
//
// Collects real TLS record sizes from pcap data or live traffic capture
// and generates TrafficProfile structs for the camouflage engine.
//
// Usage workflow:
//   1. On a clean VPS outside GFW, run tcpdump to capture real browser traffic
//   2. Extract TLS record sizes using tshark:
//      tshark -r capture.pcap -T fields -e tcp.srcport -e tcp.dstport -e tls.record.length
//   3. Feed the sizes into ProfileCollector
//   4. Export as Go code or JSON for ShadowFlow profiles
// ====================================================================

// CapturedRecord represents a single captured TLS record.
type CapturedRecord struct {
	Size      int  `json:"size"`       // TLS record payload size
	IsC2S     bool `json:"is_c2s"`     // true = client→server, false = server→client
	SeqIndex  int  `json:"seq_index"`  // Position in the connection (0-based)
	Timestamp int64 `json:"timestamp"` // Unix milliseconds
}

// ProfileCollector accumulates captured TLS records and builds profiles.
type ProfileCollector struct {
	name    string
	records []CapturedRecord
	mu      sync.Mutex
}

// NewProfileCollector creates a new collector for a named profile.
func NewProfileCollector(name string) *ProfileCollector {
	return &ProfileCollector{
		name: name,
	}
}

// AddRecord adds a captured TLS record to the collector.
func (pc *ProfileCollector) AddRecord(size int, isC2S bool, seqIndex int, timestampMs int64) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	pc.records = append(pc.records, CapturedRecord{
		Size:      size,
		IsC2S:     isC2S,
		SeqIndex:  seqIndex,
		Timestamp: timestampMs,
	})
}

// BuildProfile generates a TrafficProfile from collected records.
// It automatically determines:
//   - Weighted size distributions for C2S and S2C
//   - Initial packet sequences (first N packets)
//   - Minimum record payload size observed
func (pc *ProfileCollector) BuildProfile(initialCount int) *TrafficProfile {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	if initialCount <= 0 {
		initialCount = 4
	}

	var c2sSizes, s2cSizes []int
	var c2sInitial, s2cInitial []InitialPacket
	c2sIdx, s2cIdx := 0, 0
	minSize := 99999

	// Separate by direction and track initial packets
	for _, r := range pc.records {
		if r.Size < minSize {
			minSize = r.Size
		}
		if r.IsC2S {
			c2sSizes = append(c2sSizes, r.Size)
			if c2sIdx < initialCount {
				c2sInitial = append(c2sInitial, InitialPacket{
					MinSize: r.Size,
					MaxSize: r.Size,
				})
				c2sIdx++
			}
		} else {
			s2cSizes = append(s2cSizes, r.Size)
			if s2cIdx < initialCount {
				s2cInitial = append(s2cInitial, InitialPacket{
					MinSize: r.Size,
					MaxSize: r.Size,
				})
				s2cIdx++
			}
		}
	}

	if minSize == 99999 || minSize < 20 {
		minSize = 26
	}

	// Build size distributions using percentile-based bucketing
	c2sRanges := buildDistribution(c2sSizes)
	s2cRanges := buildDistribution(s2cSizes)

	// Widen initial packet ranges by ±20% for natural variation
	widenInitial(c2sInitial)
	widenInitial(s2cInitial)

	return &TrafficProfile{
		Name:             pc.name,
		C2SSizes:         c2sRanges,
		S2CSizes:         s2cRanges,
		C2SInitial:       c2sInitial,
		S2CInitial:       s2cInitial,
		MinRecordPayload: minSize,
		MaxRecordPayload: 16384,
	}
}

// buildDistribution creates weighted SizeRange buckets from observed sizes.
// Uses 5 percentile-based buckets to capture the distribution shape.
func buildDistribution(sizes []int) []SizeRange {
	if len(sizes) == 0 {
		return []SizeRange{{Min: 26, Max: 16384, Weight: 100}}
	}

	sort.Ints(sizes)

	// 5-bucket percentile split: 0-20%, 20-40%, 40-60%, 60-80%, 80-100%
	bucketCount := 5
	var ranges []SizeRange

	for i := 0; i < bucketCount; i++ {
		startIdx := len(sizes) * i / bucketCount
		endIdx := len(sizes) * (i + 1) / bucketCount
		if endIdx > len(sizes) {
			endIdx = len(sizes)
		}
		if startIdx >= endIdx {
			continue
		}

		bucket := sizes[startIdx:endIdx]
		ranges = append(ranges, SizeRange{
			Min:    bucket[0],
			Max:    bucket[len(bucket)-1],
			Weight: 20, // Equal weight per bucket
		})
	}

	return ranges
}

// widenInitial adds ±20% variation to initial packet ranges.
func widenInitial(initial []InitialPacket) {
	for i := range initial {
		margin := initial[i].MinSize / 5
		if margin < 5 {
			margin = 5
		}
		initial[i].MinSize -= margin
		if initial[i].MinSize < 20 {
			initial[i].MinSize = 20
		}
		initial[i].MaxSize += margin
		if initial[i].MaxSize > 16384 {
			initial[i].MaxSize = 16384
		}
	}
}

// ExportJSON exports the built profile as JSON for use in configuration.
func (pc *ProfileCollector) ExportJSON(initialCount int) ([]byte, error) {
	profile := pc.BuildProfile(initialCount)
	return json.MarshalIndent(profile, "", "  ")
}

// ExportToFile writes the profile JSON to a file.
func (pc *ProfileCollector) ExportToFile(path string, initialCount int) error {
	data, err := pc.ExportJSON(initialCount)
	if err != nil {
		return fmt.Errorf("marshal profile: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

// LoadProfileFromJSON loads a TrafficProfile from a JSON file.
// This allows importing profiles collected on remote machines.
func LoadProfileFromJSON(path string) (*TrafficProfile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read profile file: %w", err)
	}
	var profile TrafficProfile
	if err := json.Unmarshal(data, &profile); err != nil {
		return nil, fmt.Errorf("unmarshal profile: %w", err)
	}
	return &profile, nil
}

// RegisterProfile adds a profile to the global registry.
func RegisterProfile(profile *TrafficProfile) {
	registryMu.Lock()
	defer registryMu.Unlock()
	profileRegistry[profile.Name] = profile
}

// LoadAndRegisterProfile loads a profile from JSON and registers it.
func LoadAndRegisterProfile(path string) error {
	profile, err := LoadProfileFromJSON(path)
	if err != nil {
		return err
	}
	RegisterProfile(profile)
	return nil
}
