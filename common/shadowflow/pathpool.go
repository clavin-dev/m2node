// Package shadowflow — path pool engine for transport-level path rotation.
//
// Provides a pool of realistic URL paths that the server can accept
// and the client can randomly rotate through. This breaks the static
// single-path fingerprint that GFW uses to correlate proxy connections.
//
// Works with WS, gRPC (serviceName), HTTPUpgrade, and XHTTP transports.
package shadowflow

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	mathrand "math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

// ====================================================================
// Path Pool — realistic URL path rotation engine
// ====================================================================

// PathPool manages a set of URL paths for transport-level rotation.
type PathPool struct {
	paths       []string
	index       atomic.Int64
	strategy    PathStrategy
	mu          sync.RWMutex
	stopCh      chan struct{}
	stopped     atomic.Bool
	wg          sync.WaitGroup
	currentPath atomic.Value // string — the "active" path for cycling
}

// PathStrategy defines how paths are selected.
type PathStrategy int

const (
	// PathRandom picks a random path per request.
	PathRandom PathStrategy = iota
	// PathRoundRobin cycles through paths in order.
	PathRoundRobin
	// PathTimeBased switches path periodically (connection cycling).
	PathTimeBased
)

// PathPoolConfig configures the path pool.
type PathPoolConfig struct {
	// Base paths from panel config (can be templates with {id} placeholder)
	Paths []string

	// Strategy for selecting paths
	Strategy PathStrategy

	// For PathTimeBased: how often to switch (seconds)
	SwitchIntervalMin int
	SwitchIntervalMax int

	// If true, auto-generate session IDs in path templates
	DynamicIDs bool
}

// DefaultPathTemplates provides realistic path templates that mimic
// common SaaS applications. The {id} placeholder is replaced with
// a random hex string per session.
var DefaultPathTemplates = []string{
	"/api/v2/realtime/events/{id}",
	"/api/v3/notifications/stream/{id}",
	"/console/{id}/monitoring/live",
	"/dashboard/{id}/analytics/realtime",
	"/socket.io/?EIO=4&transport=websocket&sid={id}",
	"/ws/collaboration/{id}/session",
	"/cable?channel={id}",
	"/graphql/subscriptions/{id}",
	"/_next/webpack-hmr?page={id}",
	"/supabase/realtime/v1/websocket?ref={id}",
}

// NewPathPool creates a new path pool from config.
func NewPathPool(config *PathPoolConfig) *PathPool {
	pool := &PathPool{
		strategy: config.Strategy,
		stopCh:   make(chan struct{}),
	}

	// If no paths provided, use defaults
	paths := config.Paths
	if len(paths) == 0 {
		paths = DefaultPathTemplates
	}

	// Expand templates: replace {id} with random hex strings
	expanded := make([]string, 0, len(paths))
	for _, p := range paths {
		if config.DynamicIDs && strings.Contains(p, "{id}") {
			// Generate multiple instances of this template
			for i := 0; i < 3; i++ {
				id := generateSessionID()
				expanded = append(expanded, strings.ReplaceAll(p, "{id}", id))
			}
		} else if strings.Contains(p, "{id}") {
			// Single instance with one random ID
			id := generateSessionID()
			expanded = append(expanded, strings.ReplaceAll(p, "{id}", id))
		} else {
			expanded = append(expanded, p)
		}
	}

	pool.paths = expanded
	if len(pool.paths) > 0 {
		pool.currentPath.Store(pool.paths[0])
	}

	// Start time-based switcher if configured
	if config.Strategy == PathTimeBased && len(pool.paths) > 1 {
		pool.startCycler(config.SwitchIntervalMin, config.SwitchIntervalMax)
	}

	log.WithFields(log.Fields{
		"count":    len(pool.paths),
		"strategy": config.Strategy,
	}).Info("ShadowFlow: path pool initialized")

	return pool
}

// Pick returns the next path based on the strategy.
func (pp *PathPool) Pick() string {
	pp.mu.RLock()
	defer pp.mu.RUnlock()

	if len(pp.paths) == 0 {
		return "/"
	}

	switch pp.strategy {
	case PathRandom:
		return pp.paths[mathrand.Intn(len(pp.paths))]
	case PathRoundRobin:
		idx := pp.index.Add(1) - 1
		return pp.paths[idx%int64(len(pp.paths))]
	case PathTimeBased:
		if v := pp.currentPath.Load(); v != nil {
			return v.(string)
		}
		return pp.paths[0]
	default:
		return pp.paths[mathrand.Intn(len(pp.paths))]
	}
}

// All returns all paths in the pool (for server-side matching).
func (pp *PathPool) All() []string {
	pp.mu.RLock()
	defer pp.mu.RUnlock()
	result := make([]string, len(pp.paths))
	copy(result, pp.paths)
	return result
}

// Close stops the cycler.
func (pp *PathPool) Close() {
	if pp.stopped.CompareAndSwap(false, true) {
		close(pp.stopCh)
		pp.wg.Wait()
	}
}

// startCycler periodically switches the active path (for time-based strategy).
func (pp *PathPool) startCycler(minSec, maxSec int) {
	if minSec <= 0 {
		minSec = 30
	}
	if maxSec <= 0 || maxSec < minSec {
		maxSec = 120
	}

	pp.wg.Add(1)
	go func() {
		defer pp.wg.Done()
		for {
			interval := minSec + mathrand.Intn(maxSec-minSec+1)
			timer := time.NewTimer(time.Duration(interval) * time.Second)
			select {
			case <-pp.stopCh:
				timer.Stop()
				return
			case <-timer.C:
				newPath := pp.paths[mathrand.Intn(len(pp.paths))]
				old := pp.currentPath.Swap(newPath)
				log.WithFields(log.Fields{
					"from": old,
					"to":   newPath,
					"next": interval,
				}).Debug("ShadowFlow: path cycled")
			}
		}
	}()
}

// generateSessionID creates a random hex string that looks like a session/account ID.
func generateSessionID() string {
	b := make([]byte, 16) // 32 hex chars
	rand.Read(b)
	return hex.EncodeToString(b)
}

// ====================================================================
// gRPC Service Name Pool — realistic gRPC service names
// ====================================================================

// DefaultGRPCServiceNames provides realistic gRPC service names.
var DefaultGRPCServiceNames = []string{
	"google.pubsub.v1.Subscriber",
	"grpc.health.v1.Health",
	"envoy.service.discovery.v3.AggregatedDiscoveryService",
	"google.cloud.bigquery.storage.v1.BigQueryRead",
	"google.cloud.aiplatform.v1.PredictionService",
	"firebase.database.v1.FirebaseEventStream",
	"google.cloud.run.v2.Services",
}

// ====================================================================
// Path-aware WS settings builder
// ====================================================================

// WSMultiPathConfig generates a WS network settings JSON that the server
// will accept. The path is set to "/" to accept all paths.
// Clients will use paths from the pool.
func WSMultiPathConfig(originalSettings []byte) ([]byte, error) {
	// Parse original settings
	var settings map[string]interface{}
	if len(originalSettings) > 0 {
		if err := json.Unmarshal(originalSettings, &settings); err != nil {
			return nil, fmt.Errorf("parse ws settings: %w", err)
		}
	} else {
		settings = make(map[string]interface{})
	}

	// Set path to "/" to accept all incoming paths
	// Security is handled by VLESS UUID auth, not by path matching
	settings["path"] = "/"

	return json.Marshal(settings)
}

// GRPCMultiServiceConfig generates a gRPC network settings JSON that
// accepts all service names by setting an empty service name.
func GRPCMultiServiceConfig(originalSettings []byte) ([]byte, error) {
	var settings map[string]interface{}
	if len(originalSettings) > 0 {
		if err := json.Unmarshal(originalSettings, &settings); err != nil {
			return nil, fmt.Errorf("parse grpc settings: %w", err)
		}
	} else {
		settings = make(map[string]interface{})
	}

	// Empty service name = accept all
	settings["serviceName"] = ""

	return json.Marshal(settings)
}
