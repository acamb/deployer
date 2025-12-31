package main

import (
	"sync/atomic"
	"time"
)

type TimeoutHandler struct {
	lastActivity atomic.Int64
}

func (th *TimeoutHandler) Write(p []byte) (n int, err error) {
	th.lastActivity.Store(time.Now().UnixMilli())
	return len(p), nil
}

func (th *TimeoutHandler) StartMonitoring(timeout time.Duration) chan int {
	stopCh := make(chan int)
	go func() {
		defer close(stopCh)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if time.Now().UnixMilli()-th.lastActivity.Load() > int64(timeout) {
					stopCh <- 1
					return
				}
			}
		}
	}()
	return stopCh
}
