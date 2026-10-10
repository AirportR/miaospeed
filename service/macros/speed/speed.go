package speed

import (
	"context"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/juju/ratelimit"

	"github.com/airportr/miaospeed/interfaces"
	"github.com/airportr/miaospeed/preconfigs"
	"github.com/airportr/miaospeed/utils"
	"github.com/airportr/miaospeed/utils/structs"
	"github.com/airportr/miaospeed/vendors"
)

// generateUploadData
var uploadDataCache = make(map[int64][]byte)
var uploadDataMutex sync.RWMutex

func Once(speed *Speed, proxy interfaces.Vendor, cfg *interfaces.SlaveRequestConfigsV3) {
	speed.Speeds = make([]uint64, cfg.DownloadDuration)

	downloadFiles := RefetchDownloadFiles(proxy, cfg.DownloadURL)
	utils.DLogf("Speed Prefetch | Using files arr=%v", downloadFiles)

	th := int(cfg.DownloadThreading)
	var wcGroups []*WriteCounter
	var ctxCancels []context.CancelFunc

	initWG := sync.WaitGroup{}
	writingLock := sync.Mutex{}
	for i := 0; i < th; i++ {
		initWG.Add(1)
		go func() {
			wc := WriteCounter{
				RateLimit: int64(utils.GCFG.SpeedLimit) / int64(th),
			}
			cancelFunc := SingleThread(downloadFiles, proxy, cfg.DownloadDuration, &wc)

			writingLock.Lock()
			ctxCancels = append(ctxCancels, cancelFunc)
			wcGroups = append(wcGroups, &wc)
			writingLock.Unlock()

			initWG.Done()
		}()
	}
	initWG.Wait()

	// normalization
	for i := 0; i < th; i++ {
		wcGroups[i].Take()
	}

	for t := 0; t < int(cfg.DownloadDuration); t++ {
		time.Sleep(time.Second - time.Millisecond*10)
		byteLen := uint64(0)
		for i := 0; i < th; i++ {
			threadLen := wcGroups[i].Take()
			utils.DLogf("Task Thread | time=%d thread=%d speed=%d", t+1, i+1, threadLen)
			byteLen += threadLen
		}
		speed.Speeds[t] = byteLen
		speed.TotalSize += byteLen
		speed.MaxSpeed = structs.Max(speed.MaxSpeed, byteLen)
	}
	speed.AvgSpeed = speed.TotalSize / uint64(cfg.DownloadDuration)

	for i := 0; i < th; i++ {
		ctxCancels[i]()
	}
}

func SingleThread(downloadFiles []string, proxy interfaces.Vendor, timeoutSeconds int64, wc *WriteCounter) context.CancelFunc {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSeconds+1)*time.Second)
	var cancelled atomic.Bool

	downloadFilesCopy := downloadFiles[:]
	fileLen := len(downloadFilesCopy)
	readyChan := make(chan bool)

	go func() {
		isReady := false
		defer func() {
			if !isReady {
				close(readyChan)
			}
		}()

		// 100 only for safty
		for i := 0; i < 100; i++ {
			// if outside cancel or deadline meet(either by time or by hand)
			if cancelled.Load() || ctx.Err() != nil {
				return
			}
			// download file
			file := downloadFilesCopy[i%fileLen]

			sni := ""
			if strings.Contains(file, "dl.google.com") {
				sni = "www.google.com"
			}

			resp, _, err := vendors.RequestUnsafe(ctx, proxy, &interfaces.RequestOptions{
				URL: file,
				SNI: sni,
			})

			if !isReady {
				isReady = true
				close(readyChan)
			}
			if err == nil {
				var bodyReader io.Reader = nil
				if wc.RateLimit >= 1024 {
					bucket := ratelimit.NewBucketWithRate(float64(wc.RateLimit)*0.95, wc.RateLimit)
					bodyReader = ratelimit.Reader(resp.Body, bucket)
				} else {
					bodyReader = resp.Body
				}

				_, _ = io.Copy(io.Discard, io.TeeReader(bodyReader, wc))
			}
			// close body
			if resp != nil && resp.Body != nil {
				_ = resp.Body.Close()
			}
		}
	}()

	<-readyChan
	return func() {
		cancelled.Store(true)
		cancel()
	}
}

// SingleUploadThread 单线程上传测试
//func SingleUploadThread(uploadURL string, proxy interfaces.Vendor, timeoutSeconds int64, rc *ReadCounter, uploadSize int64) context.CancelFunc {
//	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSeconds+1)*time.Second)
//	isCancelled := false
//
//	readyChan := make(chan bool)
//
//	go func() {
//		isReady := false
//		defer func() {
//			if !isReady {
//				close(readyChan)
//			}
//		}()
//
//		// 生成上传数据
//		uploadData := generateUploadData(uploadSize)
//
//		// 100 only for safety
//		for i := 0; i < 100; i++ {
//			// if outside cancel or deadline meet(either by time or by hand)
//			if isCancelled || ctx.Err() != nil {
//				return
//			}
//
//			// 执行上传请求
//			resp, _, err := vendors.RequestUnsafe(ctx, proxy, &interfaces.RequestOptions{
//				URL:    uploadURL,
//				Method: "POST",
//				Body:   uploadData,
//				Headers: map[string]string{
//					"Content-Type":   "application/octet-stream",
//					"Content-Length": fmt.Sprintf("%d", len(uploadData)),
//				},
//			})
//
//			if !isReady {
//				isReady = true
//				close(readyChan)
//			}
//
//			// 读取响应body以确保请求完成
//			if err == nil && resp != nil && resp.Body != nil {
//				_, _ = io.Copy(io.Discard, resp.Body)
//			}
//
//			// close body
//			if resp != nil && resp.Body != nil {
//				_ = resp.Body.Close()
//			}
//		}
//	}()
//
//	<-readyChan
//	return func() {
//		isCancelled = true
//		cancel()
//	}
//}

func RefetchDownloadFiles(proxy interfaces.Vendor, file string) []string {
	defaultList := []string{preconfigs.SPEED_DEFAULT_LARGE_FILE_STATIC_GOOGLE}
	if proxy == nil || proxy.Status() == interfaces.VStatusNotReady {
		return defaultList
	}

	switch file {
	case preconfigs.SPEED_DEFAULT_LARGE_FILE_DYN_INTL:
		return []string{preconfigs.SPEED_DEFAULT_LARGE_FILE_STATIC_GOOGLE}
	case preconfigs.SPEED_DEFAULT_LARGE_FILE_DYN_FAST:
		body, _, _ := vendors.RequestWithRetry(proxy, 3, 1000, &interfaces.RequestOptions{
			URL:     "https://api.fast.com/netflix/speedtest/v2?https=false&token=YXNkZmFzZGxmbnNkYWZoYXNkZmhrYWxm&urlCount=5",
			NoRedir: true,
		})
		url := jsoniter.Get(body, "targets", 0, "url").ToString()
		if url != "" {
			return []string{url}
		} else {
			return defaultList
		}
	}
	return []string{file}
}

// RefetchUploadURL 获取上传URL
func RefetchUploadURL(proxy interfaces.Vendor, uploadURL string) string {
	defaultURL := preconfigs.SPEED_DEFAULT_UPLOAD_URL
	if proxy == nil || proxy.Status() == interfaces.VStatusNotReady {
		return defaultURL
	}

	switch uploadURL {
	case preconfigs.SPEED_DEFAULT_UPLOAD_URL_DYN:
		// 动态获取上传URL的逻辑
		//body, _, _ := vendors.RequestWithRetry(proxy, 3, 1000, &interfaces.RequestOptions{
		//	URL:     "https://api.speedtest.net/api/upload/servers",
		//	NoRedir: true,
		//})
		//
		//// 解析响应获取最佳上传服务器
		//// 这里可以根据实际API响应格式进行解析
		//if len(body) > 0 {
		//	// 简化处理，实际应该解析JSON获取最佳服务器
		//	return defaultURL
		//}
		// TODO 待完善动态获取上传服务器
		return defaultURL
	}
	return uploadURL
}

// UploadOnceChunked 使用 Transfer-Encoding: chunked 的上传测速
func UploadOnceChunked(speed *UploadSpeed, proxy interfaces.Vendor, cfg *interfaces.SlaveRequestConfigsV3) {
	speed.Speeds = make([]uint64, cfg.UploadDuration)
	if utils.GCFG.EnableUploadSpeedFlag == false || cfg.ApiVersion < interfaces.ApiV3 {
		return
	}
	uploadURL := RefetchUploadURL(proxy, cfg.UploadURL)
	utils.DLogf("Upload Speed (chunked) | Using upload URL=%v", uploadURL)

	th := int(cfg.UploadThreading)
	var rcGroups []*ReadCounter
	var ctxCancels []context.CancelFunc

	initWG := sync.WaitGroup{}
	writingLock := sync.Mutex{}
	for i := 0; i < th; i++ {
		initWG.Add(1)
		go func() {
			rc := ReadCounter{
				RateLimit: int64(utils.GCFG.SpeedLimit) / int64(th),
			}
			cancelFunc := SingleUploadThreadChunked(uploadURL, proxy, cfg.UploadDuration, &rc)

			writingLock.Lock()
			ctxCancels = append(ctxCancels, cancelFunc)
			rcGroups = append(rcGroups, &rc)
			writingLock.Unlock()

			initWG.Done()
		}()
	}
	initWG.Wait()

	// normalization
	for i := 0; i < th; i++ {
		rcGroups[i].Take()
	}

	for t := 0; t < int(cfg.UploadDuration); t++ {
		time.Sleep(time.Second - time.Millisecond*10)
		byteLen := uint64(0)
		for i := 0; i < th; i++ {
			threadLen := rcGroups[i].Take()
			utils.DLogf("Upload Chunked Task | time=%d thread=%d speed=%d", t+1, i+1, threadLen)
			byteLen += threadLen
		}
		speed.Speeds[t] = byteLen
		speed.TotalSize += byteLen
		speed.MaxSpeed = structs.Max(speed.MaxSpeed, byteLen)
	}
	speed.AvgSpeed = speed.TotalSize / uint64(cfg.UploadDuration)

	for i := 0; i < th; i++ {
		ctxCancels[i]()
	}
}

// SingleUploadThreadChunked 单线程 chunked 上传
func SingleUploadThreadChunked(uploadURL string, proxy interfaces.Vendor, timeoutSeconds int64, rc *ReadCounter) context.CancelFunc {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSeconds+3)*time.Second)
	var cancelled atomic.Bool
	readyChan := make(chan bool)

	go func() {
		isReady := false
		defer func() {
			if !isReady {
				close(readyChan)
			}
		}()

		chunkSize := 64 * 1024 * 2 // 256KB
		pattern := []byte(strings.Repeat("0", chunkSize))

		// 100 only for safety
		for i := 0; i < 100; i++ {
			if cancelled.Load() || ctx.Err() != nil {
				return
			}
			pr, pw := io.Pipe()
			var wg sync.WaitGroup
			writerStopped := make(chan struct{})

			// Write to both the pipe and the counter to ensure they are consistent.
			mw := io.MultiWriter(pw, rc)
			wg.Add(1)
			go func() {
				defer func() {
					wg.Done()
					close(writerStopped)
				}()

				ticker := time.NewTicker(time.Millisecond * 10)
				defer ticker.Stop()

				for {
					select {
					case <-ctx.Done():
						_ = pw.Close()
						return
					case <-ticker.C:
						select {
						case <-writerStopped:
							return
						default:
						}

						_, err := mw.Write(pattern)
						if err != nil {
							// 常见是 io.ErrClosedPipe（reader 端已关闭/请求结束）
							// 不记录错误日志，这是正常的流程控制
							_ = pw.Close()
							return
						}
					}
				}
			}()

			// 为单个请求创建更短的超时上下文，避免整体超时 | Create a shorter timeout context for each request, to avoid overall timeout.
			requestCtx, requestCancel := context.WithTimeout(ctx, time.Duration(timeoutSeconds/2)*time.Second)

			resp, _, err := vendors.RequestUnsafe(requestCtx, proxy, &interfaces.RequestOptions{
				URL:    uploadURL,
				Method: "POST",
				Reader: pr,
				Headers: map[string]string{
					"Content-Type":      "application/octet-stream",
					"Transfer-Encoding": "chunked",
				},
			})

			if !isReady {
				isReady = true
				close(readyChan)
			}

			requestCancel()
			_ = pw.Close() // ensure the writer is closed, so the writer goroutine can exit.
			wg.Wait()

			if err != nil {
				if !strings.Contains(err.Error(), "context deadline exceeded") && !strings.Contains(err.Error(), "EOF") {
					utils.DErrorf("Upload Chunked Task | Request error: %v", err)
				}
			} else {
				if resp != nil && resp.Body != nil {
					_, _ = io.Copy(io.Discard, resp.Body)
					_ = resp.Body.Close()
				}
			}

			if cancelled.Load() || ctx.Err() != nil {
				return
			}

			// Short interval to avoid tight loop.
			select {
			case <-ctx.Done():
				return
			case <-time.After(50 * time.Millisecond):
			}
		}
	}()

	<-readyChan
	return func() {
		cancelled.Store(true)
		cancel()
	}
}
