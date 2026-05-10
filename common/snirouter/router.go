// Package snirouter implements a local SNI-based TCP reverse proxy.
//
// When Reality is configured with multiple server_names, this router
// sits at 127.0.0.1:<port> as the dest target. For each incoming probe
// connection, it peeks the TLS ClientHello, extracts the SNI, and
// forwards the entire connection to the matching upstream (SNI:443).
//
// This makes active probing indistinguishable from direct connections
// to the real websites, even when multiple SNIs are in the pool.
package snirouter

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// Router is a local SNI-aware TCP reverse proxy.
type Router struct {
	listener net.Listener
	// sniMap: lowercase SNI → upstream address (e.g. "1.2.3.4:443")
	sniMap      map[string]string
	defaultDest string
	port        int
	mu          sync.RWMutex
	done        chan struct{}
}

// New creates a new SNI router.
//   - sniToDest maps each SNI domain to an upstream addr (host:port).
//     If a dest is empty, the SNI domain itself is used as the upstream.
//   - defaultDest is used when the extracted SNI doesn't match any entry.
func New(sniToDest map[string]string, defaultDest string) *Router {
	m := make(map[string]string, len(sniToDest))
	for sni, dest := range sniToDest {
		sni = strings.ToLower(strings.TrimSpace(sni))
		if sni == "" {
			continue
		}
		if dest == "" {
			dest = sni + ":443"
		} else if !strings.Contains(dest, ":") {
			dest = dest + ":443"
		}
		m[sni] = dest
	}
	if defaultDest != "" && !strings.Contains(defaultDest, ":") {
		defaultDest = defaultDest + ":443"
	}
	return &Router{
		sniMap:      m,
		defaultDest: defaultDest,
		done:        make(chan struct{}),
	}
}

// Start binds to a random local port and begins accepting connections.
func (r *Router) Start() error {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("snirouter: listen error: %w", err)
	}
	r.listener = ln
	r.port = ln.Addr().(*net.TCPAddr).Port
	log.Printf("[SNI Router] listening on 127.0.0.1:%d (%d SNI entries)", r.port, len(r.sniMap))

	go r.acceptLoop()
	return nil
}

// Port returns the local port the router is listening on.
func (r *Router) Port() int {
	return r.port
}

// Addr returns the full address string (e.g. "127.0.0.1:12345").
func (r *Router) Addr() string {
	return fmt.Sprintf("127.0.0.1:%d", r.port)
}

// Close shuts down the router.
func (r *Router) Close() error {
	close(r.done)
	if r.listener != nil {
		return r.listener.Close()
	}
	return nil
}

func (r *Router) acceptLoop() {
	for {
		conn, err := r.listener.Accept()
		if err != nil {
			select {
			case <-r.done:
				return
			default:
				log.Printf("[SNI Router] accept error: %v", err)
				continue
			}
		}
		go r.handleConn(conn)
	}
}

func (r *Router) handleConn(conn net.Conn) {
	defer conn.Close()

	// Set a deadline for reading the ClientHello
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Peek the TLS ClientHello to extract SNI without consuming data.
	// We use a tls.Server with a custom GetConfigForClient to intercept
	// the ClientHello, then replay the raw bytes to the upstream.
	var extractedSNI string
	peekConn := &peekableConn{Conn: conn}

	tlsConn := tls.Server(peekConn, &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			extractedSNI = strings.ToLower(hello.ServerName)
			// Return an error to abort the TLS handshake — we only
			// needed the ClientHello, not a full handshake.
			return nil, fmt.Errorf("sni extracted: %s", extractedSNI)
		},
	})

	// This will fail (intentionally) after extracting the SNI.
	_ = tlsConn.Handshake()

	// Clear the deadline for the proxy phase
	conn.SetReadDeadline(time.Time{})

	// Determine upstream target
	dest := r.resolve(extractedSNI)
	if dest == "" {
		log.Printf("[SNI Router] no dest for SNI=%q, dropping", extractedSNI)
		return
	}

	// Connect to upstream
	upstream, err := net.DialTimeout("tcp", dest, 5*time.Second)
	if err != nil {
		log.Printf("[SNI Router] dial upstream %s error: %v", dest, err)
		return
	}
	defer upstream.Close()

	// Replay the buffered bytes (the original ClientHello) to upstream
	if len(peekConn.buf) > 0 {
		_, err = upstream.Write(peekConn.buf)
		if err != nil {
			log.Printf("[SNI Router] replay to upstream error: %v", err)
			return
		}
	}

	// Bidirectional copy
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(upstream, conn)
		upstream.(*net.TCPConn).CloseWrite()
	}()
	go func() {
		defer wg.Done()
		io.Copy(conn, upstream)
		conn.(*net.TCPConn).CloseWrite()
	}()
	wg.Wait()
}

func (r *Router) resolve(sni string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if dest, ok := r.sniMap[sni]; ok {
		return dest
	}
	return r.defaultDest
}

// peekableConn wraps a net.Conn and buffers all data read from it,
// so we can replay the raw bytes to the upstream server later.
type peekableConn struct {
	net.Conn
	buf []byte
}

func (p *peekableConn) Read(b []byte) (int, error) {
	n, err := p.Conn.Read(b)
	if n > 0 {
		p.buf = append(p.buf, b[:n]...)
	}
	return n, err
}
