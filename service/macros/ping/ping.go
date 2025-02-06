package ping

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	urllib "net/url"
	"strings"
	"time"

	"github.com/airportr/miaospeed/interfaces"
	"github.com/airportr/miaospeed/preconfigs"
	"github.com/airportr/miaospeed/utils"
	"github.com/airportr/miaospeed/utils/structs"
)

type timeoutReader struct {
	r       *bufio.Reader
	timeout time.Time
}

func (tr *timeoutReader) Read(p []byte) (n int, err error) {
	if time.Now().After(tr.timeout) {
		return 0, errors.New("read timeout")
	}
	return tr.r.Read(p)
}

func saferParseHTTPStatus(reader *bufio.Reader) (int, error) {
	timeoutReader := &timeoutReader{reader, time.Now().Add(5 * time.Second)}
	limitedReader := io.LimitReader(timeoutReader, 1024*1024)

	resp, err := http.ReadResponse(bufio.NewReader(limitedReader), nil)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	return resp.StatusCode, nil
}

func pingViaTrace(ctx context.Context, p interfaces.Vendor, url string) (uint16, uint16, int, error) {
	transport := &http.Transport{
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return p.DialTCP(ctx, url, interfaces.ROptionsTCP)
		},
		MaxIdleConns:          100,
		IdleConnTimeout:       3 * time.Second,
		TLSHandshakeTimeout:   3 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
			// for version prior to tls1.3, the handshake will take 2-RTTs,
			// plus, majority server supports tls1.3, so we set a limit here.
			MinVersion: tls.VersionTLS13,
			RootCAs:    preconfigs.MiaokoRootCAPrepare(),
		},
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, 0, 0, err
	}

	var tlsStart, tlsEnd, writeStart, writeEnd int64
	trace := &httptrace.ClientTrace{
		TLSHandshakeStart:    func() { tlsStart = time.Now().UnixMilli() },
		TLSHandshakeDone:     func(_ tls.ConnectionState, err error) { tlsEnd = time.Now().UnixMilli() },
		GotFirstResponseByte: func() { writeEnd = time.Now().UnixMilli() },
		WroteHeaders:         func() { writeStart = time.Now().UnixMilli() },
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	connStart := time.Now().UnixMilli()
	resp, err := transport.RoundTrip(req)
	if err != nil {
		return 0, 0, 0, err
	}
	defer resp.Body.Close()

	connEnd := time.Now().UnixMilli()
	utils.DBlackhole(!strings.HasPrefix(url, "https:"), connEnd-writeEnd, writeEnd-tlsEnd, tlsEnd-tlsStart, tlsStart-connStart)

	if !strings.HasPrefix(url, "https:") {
		return uint16(writeStart - connStart), uint16(writeEnd - connStart), resp.StatusCode, nil
	}
	if resp.TLS != nil && resp.TLS.HandshakeComplete {
		return uint16(writeEnd - tlsEnd), uint16(writeEnd - connStart), resp.StatusCode, nil
	}
	return 0, 0, 0, fmt.Errorf("cannot extract payload from response")
}

func pingViaNetCat(ctx context.Context, p interfaces.Vendor, url string) (uint16, uint16, int, error) {
	purl, _ := urllib.Parse(url)
	payload := structs.X(preconfigs.NETCAT_HTTP_PAYLOAD, purl.EscapedPath()+"?"+purl.Query().Encode(), purl.Hostname(), utils.VERSION)

	connStart := time.Now()
	conn, err := p.DialTCP(ctx, url, interfaces.ROptionsTCP)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("dial failed: %w", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(6 * time.Second))
	reader := bufio.NewReader(conn)

	if _, err := conn.Write([]byte(payload)); err != nil {
		return 0, 0, 0, fmt.Errorf("write failed 1: %w", err)
	}
	_, _ = reader.ReadByte() // Flush buffer
	connRTT := time.Since(connStart).Milliseconds()
	//_, _, _ = reader.ReadLine()
	for reader.Buffered() > 0 {
		_, _, _ = reader.ReadLine()
	}
	tcpStart := time.Now()
	if _, err := conn.Write([]byte(payload)); err != nil {
		return 0, 0, 0, fmt.Errorf("write failed 2: %w", err)
	}
	if _, err := reader.Peek(1); err != nil {
		return 0, 0, 0, fmt.Errorf("read failed 3: %w", err)
	}

	tcpRTT := time.Since(tcpStart).Milliseconds()
	statusCode, err := saferParseHTTPStatus(reader)
	if err != nil {
		return uint16(tcpRTT), 0, 0, nil
	}
	return uint16(tcpRTT), uint16(connRTT), statusCode, nil
}

func ping(obj *Ping, p interfaces.Vendor, url string, withAvg uint16, timeout uint) {
	var (
		rttTimes      []uint16
		requestTimes  []uint16
		statusCodes   []int
		failedAttempt uint
	)

	if p == nil {
		initFailedPing(obj)
		return
	}

	for i := 0; i < int(withAvg); i++ {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Millisecond)
		rtt, req, code, err := performPing(ctx, p, url)
		cancel()

		if err != nil {
			//utils.DLogf("ping failed: %v", err)
			failedAttempt++
			continue
		}

		updatePingMetrics(obj, rtt, req)
		rttTimes = append(rttTimes, rtt)
		requestTimes = append(requestTimes, req)
		statusCodes = append(statusCodes, code)
	}

	calculateFinalMetrics(obj, rttTimes, requestTimes, statusCodes, failedAttempt, withAvg)
}

func initFailedPing(obj *Ping) {
	obj.RTT = 0
	obj.Request = 0
	obj.PacketLoss = 100.0
	obj.Jitter = 0
	obj.RTTList = nil
	obj.RequestList = nil
	obj.StatusCodes = nil
}

func performPing(ctx context.Context, p interfaces.Vendor, url string) (uint16, uint16, int, error) {
	if strings.HasPrefix(url, "https:") {
		return pingViaTrace(ctx, p, url)
	}
	return pingViaNetCat(ctx, p, url)
}

func updatePingMetrics(obj *Ping, rtt, req uint16) {
	obj.MaxRTT = structs.Max(obj.MaxRTT, rtt)
	obj.MaxRequest = structs.Max(obj.MaxRequest, req)
}

func calculateFinalMetrics(obj *Ping, rtts, reqs []uint16, codes []int, failed uint, total uint16) {
	obj.PacketLoss = float64(failed) / float64(total) * 100
	obj.StatusCodes = codes

	if len(rtts) > 0 {
		obj.RTT = calcAvgPing(rtts)
		obj.Jitter = calcStdDevPing(rtts)
		obj.RTTSD = obj.Jitter
		obj.RTTList = rtts
	}
	if len(reqs) > 0 {
		obj.Request = calcAvgPing(reqs)
		obj.RequestSD = calcStdDevPing(reqs)
		obj.RequestList = reqs
	}
}

//func calcAvgPing(values []uint16) uint16 {
//	if len(values) == 0 {
//		return 0
//	}
//	var sum uint32
//	for _, v := range values {
//		sum += uint32(v)
//	}
//	return uint16(sum / uint32(len(values)))
//}
//
//func calcStdDevPing(values []uint16) uint16 {
//	if len(values) < 2 {
//		return 0
//	}
//	mean := calcAvgPing(values)
//	var variance float64
//	for _, v := range values {
//		diff := float64(int32(v) - int32(mean))
//		variance += diff * diff
//	}
//	variance /= float64(len(values) - 1)
//	return uint16(variance)
//}
