package speed

import "sync/atomic"

type WriteCounter struct {
	Total     atomic.Uint64
	RateLimit int64
}

func (wc *WriteCounter) Write(p []byte) (int, error) {
	n := len(p)
	wc.Total.Add(uint64(n))
	return n, nil
}

func (wc *WriteCounter) Take() uint64 {
	return wc.Total.Swap(0)
}
