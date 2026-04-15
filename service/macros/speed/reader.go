package speed

import "sync/atomic"

// ReadCounter 上传计数器（对应下载的WriteCounter）
type ReadCounter struct {
	count     atomic.Uint64
	RateLimit int64
}

func (rc *ReadCounter) Write(p []byte) (n int, err error) {
	n = len(p)
	rc.count.Add(uint64(n))
	return n, nil
}

func (rc *ReadCounter) Take() uint64 {
	return rc.count.Swap(0)
}
