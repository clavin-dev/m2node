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

	executing atomic.Int32 // guard against goroutine pile-up
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
	// Prevent goroutine pile-up: if the previous execution is still
	// running (leaked goroutine from a timeout), skip this cycle entirely.
	if !t.executing.CompareAndSwap(0, 1) {
		log.Warnf("Task %s previous execution still running, skipping this cycle", t.Name)
		return
	}

	timeout := min(5*t.Interval, 5*time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)

	// Store cancel so Close() can abort a stuck task
	t.Access.Lock()
	t.cancel = cancel
	t.Access.Unlock()

	// Run synchronously — context timeout handles HTTP call cancellation.
	// This eliminates the goroutine leak entirely: no orphaned goroutines
	// can accumulate and create mapLock write-starvation deadlocks.
	err := t.Execute(ctx)
	cancel()
	t.executing.Store(0)

	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			log.Warnf("Task %s execution timed out, will retry next cycle", t.Name)
			return
		}
		log.Errorf("Task %s execution error: %v", t.Name, err)
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
