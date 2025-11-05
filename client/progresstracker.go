package client

import (
	"fmt"
	"math"
	"sync/atomic"
	"time"
)

type ProgressTracker struct {
	StartTime        int64
	BytesTotal       int64
	BytesTransferred int64
	LastReportTime   int64
	stopCh           chan struct{}
}

func (pt *ProgressTracker) Write(data []byte) (int, error) {
	size := int64(len(data))
	atomic.AddInt64(&pt.BytesTransferred, size)
	return int(size), nil
}

func (pt *ProgressTracker) StartReporting() {
	pt.StartTime = time.Now().Unix()
	pt.stopCh = make(chan struct{})
	go func() {
		tick := time.NewTicker(1 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-pt.stopCh:
				pt.printFinal()
				return
			case <-tick.C:
				pt.printProgress()
			}
		}
	}()
}

func (pt *ProgressTracker) printProgress() {
	total := atomic.LoadInt64(&pt.BytesTotal)
	done := atomic.LoadInt64(&pt.BytesTransferred)
	percentage := float64(done) / float64(total) * 100
	elapsed := time.Now().Unix() - pt.StartTime
	if elapsed <= 0 {
		elapsed = 1
	}
	speed := float64(done/(1024*1024)) / float64(elapsed)
	remainingBytes := total - done
	var etaSec int
	if speed > 0 {
		etaSec = int(float64(remainingBytes) / speed)
	}
	fmt.Printf("\r\033[KProgress: %3.0f%%  Speed: %0.0f MB/s  Remaining: %ds", percentage, speed, etaSec)
}

func (pt *ProgressTracker) printFinal() {
	done := atomic.LoadInt64(&pt.BytesTransferred)
	elapsed := time.Now().Unix() - pt.StartTime
	speed := float64(done) / float64(math.Max(float64(elapsed), 1.0)) / (1024 * 1024)
	fmt.Printf("\r\033[KCompleted. Transfered: %d MB in %ds (%0.0f MB/s)\n", done/(1024*1024), elapsed, speed)
}

func (pt *ProgressTracker) StopReporting() {
	select {
	case <-pt.stopCh:
	default:
		close(pt.stopCh)
	}
}
