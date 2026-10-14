package usecase

import (
	"context"
	"sync"
	"time"
)

// Run starts one sequential worker per appliance and joins them on cancellation.
// Report may run concurrently; the caller supplies a concurrency-safe handler.
func Run(ctx context.Context, workers []*Worker, report func(CycleResult, error)) {
	var wg sync.WaitGroup
	for _, worker := range workers {
		wg.Go(func() {
			for ctx.Err() == nil {
				result, err := worker.Cycle(ctx)
				if ctx.Err() != nil {
					return
				}
				report(result, err)
				timer := time.NewTimer(result.NextDelay)
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
			}
		})
	}
	wg.Wait()
}
