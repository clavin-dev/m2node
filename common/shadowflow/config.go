package shadowflow

import (
	"encoding/json"
	"sync"

	log "github.com/sirupsen/logrus"
)

// ====================================================================
// Panel Config Bridge
//
// Receives ShadowFlow configuration from the v2board panel API and
// translates it into CamouflageEngine + DomainRouter instances.
//
// Config flow:
//   Panel DB → PHP API → JSON → Go CommonNode → NodeConfig → Engine
// ====================================================================

// NodeConfig holds all ShadowFlow settings for one node,
// parsed from the panel's JSON API response.
type NodeConfig struct {
	// Camouflage mode: "web_browsing", "live_stream", "file_download",
	// "video_call", "random", "dynamic"
	Camouflage string `json:"camouflage"`

	// Detailed shaping settings (from shaping_settings JSON)
	Shaping *ShapingConfig `json:"shaping,omitempty"`

	// SNI mode: "random" or "fixed"
	SniMode string `json:"sni_mode"`

	// Dynamic switching intervals (seconds)
	SwitchIntervalMin int `json:"switch_interval_min"`
	SwitchIntervalMax int `json:"switch_interval_max"`

	// CDN domain pools (newline-separated)
	UploadHost   string `json:"upload_host"`
	DownloadHost string `json:"download_host"`

	// Path pool for transport-level path rotation (newline-separated)
	PathPool string `json:"path_pool"`

	// Connection max lifetime in seconds (0 = no limit).
	// When set, connections are cycled periodically to switch paths.
	ConnMaxLifetime int `json:"conn_max_lifetime"`

	// Transport mode: "tcp", "ws", "grpc", "reality"
	TransportType string `json:"transport_type"`

	// Transport path for ws/grpc (e.g. "/ws", "/grpc.service/Method")
	TransportPath string `json:"transport_path"`

	// Transport host for ws/grpc CDN (e.g. "cdn.example.com")
	TransportHost string `json:"transport_host"`
}

// ShapingConfig is the parsed shaping_settings JSON from the panel.
type ShapingConfig struct {
	// Profile name override: "chrome_h2", "safari", "firefox"
	Profile string `json:"profile"`

	// Custom profiles to load from JSON files
	CustomProfiles []string `json:"custom_profiles"`

	// Noise injection settings
	NoiseEnabled       bool `json:"noise_enabled"`
	NoiseAggressiveMs  int  `json:"noise_aggressive_ms"`
	NoiseBackgroundSec int  `json:"noise_background_sec"`

	// Connection pool settings
	PoolEnabled  bool `json:"pool_enabled"`
	PoolMaxConns int  `json:"pool_max_conns"`
	PoolMaxAge   int  `json:"pool_max_age_sec"`

	// Domain rotation strategy: "random", "round_robin", "time_based"
	DomainStrategy string `json:"domain_strategy"`
}

// configStore holds per-tag NodeConfig for the dispatcher to query.
var configStore sync.Map // map[tag]*NodeConfig

// SetNodeConfig stores the ShadowFlow config for a node tag.
// Called when a node is added/updated from the panel.
func SetNodeConfig(tag string, config *NodeConfig) {
	configStore.Store(tag, config)
	log.WithFields(log.Fields{
		"tag":        tag,
		"camouflage": config.Camouflage,
		"sni_mode":   config.SniMode,
		"switch_min": config.SwitchIntervalMin,
		"switch_max": config.SwitchIntervalMax,
		"upload":     config.UploadHost,
		"download":   config.DownloadHost,
	}).Info("ShadowFlow: node config stored")
}

// GetNodeConfig retrieves the ShadowFlow config for a node tag.
func GetNodeConfig(tag string) *NodeConfig {
	if v, ok := configStore.Load(tag); ok {
		return v.(*NodeConfig)
	}
	return nil
}

// DeleteNodeConfig removes config when a node is deleted.
func DeleteNodeConfig(tag string) {
	configStore.Delete(tag)
}

// ParseFromCommonNode creates a NodeConfig from the raw API fields.
// This is called during node info parsing.
func ParseFromCommonNode(camouflage string, shapingSettingsRaw json.RawMessage,
	sniMode string, switchMin, switchMax int,
	uploadHost, downloadHost string,
	pathPool string, connMaxLifetime int,
	transportType, transportPath, transportHost string) *NodeConfig {

	config := &NodeConfig{
		Camouflage:        camouflage,
		SniMode:           sniMode,
		SwitchIntervalMin: switchMin,
		SwitchIntervalMax: switchMax,
		UploadHost:        uploadHost,
		DownloadHost:      downloadHost,
		PathPool:          pathPool,
		ConnMaxLifetime:   connMaxLifetime,
		TransportType:     transportType,
		TransportPath:     transportPath,
		TransportHost:     transportHost,
	}

	// Defaults
	if config.Camouflage == "" {
		config.Camouflage = "random"
	}
	if config.SniMode == "" {
		config.SniMode = "random"
	}
	if config.SwitchIntervalMin <= 0 {
		config.SwitchIntervalMin = 30
	}
	if config.SwitchIntervalMax <= 0 || config.SwitchIntervalMax < config.SwitchIntervalMin {
		config.SwitchIntervalMax = 120
	}
	if config.TransportType == "" {
		config.TransportType = "tcp"
	}
	if config.TransportPath == "" {
		config.TransportPath = "/ws"
	}

	// Parse shaping_settings JSON
	if len(shapingSettingsRaw) > 0 {
		var shaping ShapingConfig
		if err := json.Unmarshal(shapingSettingsRaw, &shaping); err == nil {
			config.Shaping = &shaping
		}
	}

	return config
}

// BuildCamouflageEngine creates a CamouflageEngine from NodeConfig.
func BuildCamouflageEngine(config *NodeConfig) *CamouflageEngine {
	// Determine profile
	profile := ChromeH2Profile
	if config.Shaping != nil && config.Shaping.Profile != "" {
		if p := GetProfile(config.Shaping.Profile); p != nil {
			profile = p
		}
	}

	// Determine mode
	mode := config.Camouflage
	if mode == "" {
		mode = "random"
	}

	engine := NewCamouflageEngine(&CamouflageConfig{
		Profile:           profile,
		Mode:              mode,
		SwitchIntervalMin: config.SwitchIntervalMin,
		SwitchIntervalMax: config.SwitchIntervalMax,
	})

	// Load custom profiles if specified
	if config.Shaping != nil {
		for _, path := range config.Shaping.CustomProfiles {
			if err := LoadAndRegisterProfile(path); err != nil {
				log.WithField("path", path).Warn("ShadowFlow: failed to load custom profile")
			}
		}
	}

	return engine
}

// BuildDomainRouter creates a DomainRouter from NodeConfig.
func BuildDomainRouter(config *NodeConfig) *DomainRouter {
	strategy := RotateRandom
	if config.Shaping != nil {
		switch config.Shaping.DomainStrategy {
		case "round_robin":
			strategy = RotateRoundRobin
		case "time_based":
			strategy = RotateTimeBased
		}
	}

	return NewDomainRouter(&DomainRouterConfig{
		UploadHosts:       config.UploadHost,
		DownloadHosts:     config.DownloadHost,
		Strategy:          strategy,
		SwitchIntervalSec: config.SwitchIntervalMin,
	})
}
