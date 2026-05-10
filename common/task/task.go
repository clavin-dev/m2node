package task

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

type Task struct {
	Name     string
	Interval time.Duration
	Execute  func(context.Context) error
	Access   sync.RWMutex
	Running  bool
	ReloadCh chan struct{}
	Stop     chan struct{}

	executing atomic.Int32    // guard: 1 = a goroutine is running Execute
	cancel    context.CancelFunc
}

func (t *Task) Start(first bool) error {
	t.Access.Lock()
	if t.Running {
		t.Access.Unlock()
		return nil
	}
	t.Running = true
	t.Stop = make(chan struct{})
	t.Access.Unlock()
	go func() {
		timer := time.NewTimer(t.Interval)
		defer timer.Stop()
		if first {
			t.executeTask()
		}

		for {
			timer.Reset(t.Interval)
			select {
			case <-timer.C:
				// continue
			case <-t.Stop:
				return
			}

			t.executeTask()
		}
	}()

	return nil
}

func (t *Task) executeTask() {
	// Guard: if a leaked goroutine from a previous timeout is still
	// running Execute, skip this cycle to prevent pile-up.
	if !t.executing.CompareAndSwap(0, 1) {
		log.Infof("Task %s previous execution still running, skipping this cycle", t.Name)
		return
	}

	// 2*Interval is enough: resty has 15s timeout + 1 retry = 30s per HTTP call.
	// Cap at 2 minutes so stuck connections are killed quickly.
	timeout := min(2*t.Interval, 2*time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)

	// Store cancel so Close() can abort a stuck task
	t.Access.Lock()
	t.cancel = cancel
	t.Access.Unlock()

	done := make(chan error, 1)
	go func() {
		done <- t.Execute(ctx)
	}()

	select {
	case err := <-done:
		// Goroutine completed within timeout — release guard
		cancel()
		t.executing.Store(0)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				log.Warnf("Task %s context cancelled, will retry next cycle", t.Name)
				return
			}
			log.Errorf("Task %s execution error: %v", t.Name, err)
		}

	case <-ctx.Done():
		// Timeout: cancel the context so the goroutine's HTTP calls abort.
		// Immediately reset the guard so the next cycle can spawn a fresh
		// execution. The old goroutine may leak if it ignores context
		// cancellation (e.g. stuck TLS handshake), but it holds minimal
		// memory and will eventually be collected when the process exits.
		cancel()
		t.executing.Store(0)
		log.Warnf("Task %s execution timed out, will retry next cycle", t.Name)
	}
}

func (t *Task) safeStop() {
	t.Access.Lock()
	if t.Running {
		t.Running = false
		close(t.Stop)
		if t.cancel != nil {
			t.cancel()
		}
	}
	t.Access.Unlock()
}

func (t *Task) Close() {
	t.safeStop()
	log.Warningf("Task %s stopped", t.Name)
}
