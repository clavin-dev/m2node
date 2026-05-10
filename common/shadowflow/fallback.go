package shadowflow

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

// ====================================================================
// Active Probe Defense — Fallback Web Server
//
// When GFW actively probes the ShadowFlow port, it should see a
// completely normal web server. This module provides a reverse proxy
// that serves real website content to non-authenticated connections.
//
// Detection flow:
//   GFW probe → [connect to port 443]
//              → [TLS handshake → Reality handles this]
//              → [sends HTTP request]
//              → [FallbackServer responds with real web content] ✅
//              → GFW concludes: normal website
//
// This is an additional layer on top of Reality's TLS-level fallback.
// Reality handles TLS probe responses; this handles HTTP-level probes.
// ====================================================================

// FallbackConfig configures the fallback web server.
type FallbackConfig struct {
	// TargetURL is the website to reverse-proxy for probe responses
	// e.g., "https://www.apple.com"
	TargetURL string

	// LocalPages serve static content if reverse proxy fails
	// map[path]content, e.g., {"/": "<html>..."}
	LocalPages map[string]string

	// ServerHeader mimics a real web server's Server header
	ServerHeader string
}

// FallbackServer serves real web content to non-authenticated probes.
type FallbackServer struct {
	config  *FallbackConfig
	client  *http.Client
	handler http.Handler
	stats   FallbackStats
}

// FallbackStats tracks probe detection metrics.
type FallbackStats struct {
	ProbesReceived atomic.Int64
	ProbesServed   atomic.Int64
}

// NewFallbackServer creates a fallback web server.
func NewFallbackServer(config *FallbackConfig) *FallbackServer {
	if config.ServerHeader == "" {
		config.ServerHeader = "nginx/1.24.0"
	}

	fs := &FallbackServer{
		config: config,
		client: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
	}

	fs.handler = http.HandlerFunc(fs.handleProbe)
	return fs
}

// Handler returns the HTTP handler for integration with the main server.
func (fs *FallbackServer) Handler() http.Handler {
	return fs.handler
}

// handleProbe serves a response that mimics a real website.
func (fs *FallbackServer) handleProbe(w http.ResponseWriter, r *http.Request) {
	fs.stats.ProbesReceived.Add(1)

	// Set standard headers that a real web server would send
	w.Header().Set("Server", fs.config.ServerHeader)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

	// Try reverse proxy to target URL
	if fs.config.TargetURL != "" {
		if fs.reverseProxy(w, r) {
			fs.stats.ProbesServed.Add(1)
			return
		}
	}

	// Fallback to local pages
	if fs.config.LocalPages != nil {
		if content, ok := fs.config.LocalPages[r.URL.Path]; ok {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(content))
			fs.stats.ProbesServed.Add(1)
			return
		}
	}

	// Default: serve a minimal but realistic 404 page
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte(defaultNotFoundPage))
	fs.stats.ProbesServed.Add(1)

	log.WithFields(log.Fields{
		"remote": r.RemoteAddr,
		"path":   r.URL.Path,
		"ua":     r.UserAgent(),
	}).Debug("ShadowFlow: served fallback page to probe")
}

// reverseProxy fetches content from the target URL and serves it.
func (fs *FallbackServer) reverseProxy(w http.ResponseWriter, r *http.Request) bool {
	targetURL := strings.TrimRight(fs.config.TargetURL, "/") + r.URL.Path
	req, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, nil)
	if err != nil {
		return false
	}

	// Copy essential headers from the probe request
	req.Header.Set("User-Agent", r.UserAgent())
	req.Header.Set("Accept", r.Header.Get("Accept"))
	req.Header.Set("Accept-Language", r.Header.Get("Accept-Language"))

	resp, err := fs.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// Copy response headers
	for key, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}
	// Override Server header with our configured value
	w.Header().Set("Server", fs.config.ServerHeader)

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
	return true
}

// GetStats returns current probe statistics.
func (fs *FallbackServer) GetStats() (received, served int64) {
	return fs.stats.ProbesReceived.Load(), fs.stats.ProbesServed.Load()
}

// IsProbe attempts to identify if a connection is likely a probe.
// Call this early in the connection handling to decide routing.
func IsProbe(conn net.Conn, timeout time.Duration) bool {
	// Heuristic: probes typically:
	// 1. Come from known GFW IP ranges (not implemented - requires ip list)
	// 2. Send unusual TLS extensions
	// 3. Disconnect quickly after response
	// 4. Don't authenticate properly
	//
	// This is a placeholder for future heuristic detection.
	// Currently, Reality handles TLS-level probing, and
	// FallbackServer handles HTTP-level probing.
	return false
}

// Default 404 page matching nginx default error page style
const defaultNotFoundPage = `<!DOCTYPE html>
<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>nginx/1.24.0</center>
</body>
</html>
`
