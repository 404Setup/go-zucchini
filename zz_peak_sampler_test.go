//go:build zucchini_memprobe || zucchini_asmcorpus

package zucchini

import (
	"runtime"
	"sync/atomic"
	"time"
)

type peakSampler struct {
	stop     chan struct{}
	done     chan struct{}
	maxHeap  atomic.Uint64
	maxSys   atomic.Uint64
	maxTotal atomic.Uint64
}

func startPeakSampler() *peakSampler {
	p := &peakSampler{stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(p.done)
		var stats runtime.MemStats
		ticker := time.NewTicker(2 * time.Millisecond)
		defer ticker.Stop()
		for {
			runtime.ReadMemStats(&stats)
			if stats.HeapAlloc > p.maxHeap.Load() {
				p.maxHeap.Store(stats.HeapAlloc)
			}
			if stats.Sys > p.maxSys.Load() {
				p.maxSys.Store(stats.Sys)
			}
			p.maxTotal.Store(stats.TotalAlloc)
			select {
			case <-p.stop:
				return
			case <-ticker.C:
			}
		}
	}()
	return p
}

func (p *peakSampler) finish() (heap, sys, total uint64) {
	close(p.stop)
	<-p.done
	return p.maxHeap.Load(), p.maxSys.Load(), p.maxTotal.Load()
}

func mib(value uint64) float64 { return float64(value) / (1 << 20) }
