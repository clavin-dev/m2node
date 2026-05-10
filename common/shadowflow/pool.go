package shadowflow

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

// ====================================================================
// Connection Pool
//
// Reuses long-lived outer TLS connections to multiplex multiple user
// streams. This dilutes the inner TLS handshake signal — instead of
// each connection having a clear handshake→data pattern, handshakes
// from different users overlap with normal data traffic.
//
// Benefits:
//   1. Inner TLS handshakes are mixed into ongoing data flow
//   2. Reduced connection establishment overhead
//   3. GFW sees fewer new connections (less suspicious)
//   4. Connection lifetime doesn't correlate with user sessions
// ====================================================================

// PooledConn wraps a net.Conn with pool management metadata.
type PooledConn struct {
	net.Conn
	pool      *ConnPool
	createdAt time.Time
	lastUsed  atomic.Value // time.Time
	inUse     atomic.Bool
	streams   atomic.Int32 // active stream count
	id        uint64
}

func (pc *PooledConn) updateLastUsed() {
	pc.lastUsed.Store(time.Now())
}

// Release returns the connection to the pool instead of closing it.
func (pc *PooledConn) Release() {
	pc.streams.Add(-1)
	if pc.streams.Load() <= 0 {
		pc.inUse.Store(false)
	}
	pc.updateLastUsed()
}

// ConnPool manages a pool of reusable connections.
type ConnPool struct {
	dialer   func() (net.Conn, error) // creates new underlying connections
	conns    []*PooledConn
	mu       sync.Mutex
	maxConns int           // maximum connections in pool
	maxAge   time.Duration // max connection lifetime
	maxIdle  time.Duration // max idle time before eviction
	nextID   atomic.Uint64

	stopCh  chan struct{}
	stopped atomic.Bool
	wg      sync.WaitGroup
}

// PoolConfig configures the connection pool.
type PoolConfig struct {
	MaxConns    int           // Max connections (default: 8)
	MaxAge      time.Duration // Max connection lifetime (default: 10min)
	MaxIdle     time.Duration // Max idle time (default: 60s)
	Dialer      func() (net.Conn, error)
}

// NewConnPool creates a connection pool.
func NewConnPool(config *PoolConfig) *ConnPool {
	maxConns := config.MaxConns
	if maxConns <= 0 {
		maxConns = 8
	}
	maxAge := config.MaxAge
	if maxAge <= 0 {
		maxAge = 10 * time.Minute
	}
	maxIdle := config.MaxIdle
	if maxIdle <= 0 {
		maxIdle = 60 * time.Second
	}

	pool := &ConnPool{
		dialer:   config.Dialer,
		maxConns: maxConns,
		maxAge:   maxAge,
		maxIdle:  maxIdle,
		stopCh:   make(chan struct{}),
	}

	// Start evictor goroutine
	pool.wg.Add(1)
	go pool.evictLoop()

	return pool
}

// Get returns an available connection from the pool, or creates a new one.
// It prefers connections with existing active streams (to maximize multiplexing).
func (p *ConnPool) Get() (*PooledConn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()

	// First pass: find a connection with room for more streams
	// (prefer connections already in use — better multiplexing)
	for _, pc := range p.conns {
		if now.Sub(pc.createdAt) > p.maxAge {
			continue // expired
		}
		if pc.streams.Load() < 32 { // max 32 streams per connection
			pc.streams.Add(1)
			pc.inUse.Store(true)
			pc.updateLastUsed()
			return pc, nil
		}
	}

	// No available connection — create new one
	if len(p.conns) >= p.maxConns {
		// Pool is full — evict oldest idle connection
		p.evictOldest()
	}

	conn, err := p.dialer()
	if err != nil {
		return nil, err
	}

	pc := &PooledConn{
		Conn:      conn,
		pool:      p,
		createdAt: now,
		id:        p.nextID.Add(1),
	}
	pc.lastUsed.Store(now)
	pc.inUse.Store(true)
	pc.streams.Store(1)

	p.conns = append(p.conns, pc)

	log.WithFields(log.Fields{
		"pool_size": len(p.conns),
		"conn_id":   pc.id,
	}).Debug("ShadowFlow: new pooled connection")

	return pc, nil
}

// evictOldest removes the oldest idle connection from the pool.
func (p *ConnPool) evictOldest() {
	var oldestIdx int = -1
	var oldestTime time.Time

	for i, pc := range p.conns {
		if pc.inUse.Load() {
			continue
		}
		lu, ok := pc.lastUsed.Load().(time.Time)
		if !ok {
			continue
		}
		if oldestIdx == -1 || lu.Before(oldestTime) {
			oldestIdx = i
			oldestTime = lu
		}
	}

	if oldestIdx >= 0 {
		p.conns[oldestIdx].Conn.Close()
		p.conns = append(p.conns[:oldestIdx], p.conns[oldestIdx+1:]...)
	}
}

// evictLoop periodically removes expired and idle connections.
func (p *ConnPool) evictLoop() {
	defer p.wg.Done()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopCh:
			return
		case <-ticker.C:
			p.mu.Lock()
			now := time.Now()
			surviving := make([]*PooledConn, 0, len(p.conns))
			for _, pc := range p.conns {
				expired := now.Sub(pc.createdAt) > p.maxAge
				lu, _ := pc.lastUsed.Load().(time.Time)
				idle := !pc.inUse.Load() && now.Sub(lu) > p.maxIdle

				if expired || idle {
					pc.Conn.Close()
					log.WithField("conn_id", pc.id).Debug("ShadowFlow: evicted pooled connection")
				} else {
					surviving = append(surviving, pc)
				}
			}
			p.conns = surviving
			p.mu.Unlock()
		}
	}
}

// Close shuts down the pool and closes all connections.
func (p *ConnPool) Close() error {
	if p.stopped.CompareAndSwap(false, true) {
		close(p.stopCh)
		p.wg.Wait()

		p.mu.Lock()
		defer p.mu.Unlock()
		for _, pc := range p.conns {
			pc.Conn.Close()
		}
		p.conns = nil
	}
	return nil
}

// Stats returns current pool statistics.
func (p *ConnPool) Stats() PoolStats {
	p.mu.Lock()
	defer p.mu.Unlock()

	stats := PoolStats{
		TotalConns: len(p.conns),
	}
	for _, pc := range p.conns {
		if pc.inUse.Load() {
			stats.ActiveConns++
		} else {
			stats.IdleConns++
		}
		stats.TotalStreams += int(pc.streams.Load())
	}
	return stats
}

// PoolStats holds pool status information.
type PoolStats struct {
	TotalConns   int
	ActiveConns  int
	IdleConns    int
	TotalStreams  int
}

// ====================================================================
// Noise-injecting PooledConn wrapper
//
// When a new stream starts on a pooled connection, inject noise to
// mask the inner TLS handshake of the new stream among existing data.
// ====================================================================

// NoisyPooledConn wraps a PooledConn with automatic noise injection
// when a new stream starts.
type NoisyPooledConn struct {
	*PooledConn
	engine   *CamouflageEngine
	injector *NoiseInjector
}

// NewNoisyPooledConn wraps a pooled connection with noise injection.
func NewNoisyPooledConn(pc *PooledConn, engine *CamouflageEngine) *NoisyPooledConn {
	npc := &NoisyPooledConn{
		PooledConn: pc,
		engine:     engine,
	}
	return npc
}

// StartStream begins a new stream on this connection.
// It injects noise to mask the inner TLS handshake timing.
func (npc *NoisyPooledConn) StartStream() (io.ReadWriteCloser, error) {
	// Inject initial noise to break handshake timing
	injector := NewNoiseInjector(npc.Conn, npc.engine)
	if err := injector.InjectInitialNoise(); err != nil {
		return nil, err
	}

	// Start background noise during the handshake window
	injector.StartContinuousNoise()
	npc.injector = injector

	return &streamWrapper{
		conn:     npc,
		injector: injector,
	}, nil
}

type streamWrapper struct {
	conn     *NoisyPooledConn
	injector *NoiseInjector
	closed   atomic.Bool
}

func (sw *streamWrapper) Read(p []byte) (int, error) {
	return sw.conn.Conn.Read(p)
}

func (sw *streamWrapper) Write(p []byte) (int, error) {
	return sw.conn.Conn.Write(p)
}

func (sw *streamWrapper) Close() error {
	if sw.closed.CompareAndSwap(false, true) {
		sw.injector.Stop()
		sw.conn.Release()
	}
	return nil
}
