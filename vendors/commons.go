package vendors

import (
	"bytes"
	"container/list"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"reflect"
	"sync"
	"time"

	"github.com/airportr/miaospeed/interfaces"
	"github.com/airportr/miaospeed/utils"
	"github.com/airportr/miaospeed/utils/structs"
)

const requestTransportCacheLimit = 128

type requestTransportCacheKey struct {
	vendorRef string
	network   interfaces.RequestOptionsNetwork
	sni       string
}

type requestTransportCacheEntry struct {
	key       requestTransportCacheKey
	transport *http.Transport
}

type requestTransportLRU struct {
	lock       sync.Mutex
	entries    map[requestTransportCacheKey]*list.Element
	lru        *list.List
	maxEntries int
}

func newRequestTransportLRU(maxEntries int) *requestTransportLRU {
	if maxEntries <= 0 {
		maxEntries = 1
	}

	return &requestTransportLRU{
		entries:    make(map[requestTransportCacheKey]*list.Element),
		lru:        list.New(),
		maxEntries: maxEntries,
	}
}

func (c *requestTransportLRU) getOrInit(key requestTransportCacheKey, init func() *http.Transport) *http.Transport {
	c.lock.Lock()
	defer c.lock.Unlock()

	if ele, ok := c.entries[key]; ok {
		c.lru.MoveToFront(ele)
		if entry, ok := ele.Value.(*requestTransportCacheEntry); ok && entry != nil && entry.transport != nil {
			return entry.transport
		}
	}

	transport := init()
	entry := &requestTransportCacheEntry{
		key:       key,
		transport: transport,
	}
	ele := c.lru.PushFront(entry)
	c.entries[key] = ele

	for len(c.entries) > c.maxEntries {
		c.removeOldestLocked()
	}

	return transport
}

func (c *requestTransportLRU) removeOldestLocked() {
	ele := c.lru.Back()
	if ele == nil {
		return
	}

	c.lru.Remove(ele)
	entry, ok := ele.Value.(*requestTransportCacheEntry)
	if !ok || entry == nil {
		return
	}

	delete(c.entries, entry.key)
	if entry.transport != nil {
		entry.transport.CloseIdleConnections()
	}
}

var requestTransportCache = newRequestTransportLRU(requestTransportCacheLimit)

func vendorReference(p interfaces.Vendor) string {
	if p == nil {
		return "<nil>"
	}

	rv := reflect.ValueOf(p)
	if rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			return fmt.Sprintf("%T@<nil>", p)
		}
		return fmt.Sprintf("%T@%x", p, rv.Pointer())
	}

	return fmt.Sprintf("%T@%v", p, p.ProxyInfo())
}

func getOrInitTransport(p interfaces.Vendor, network interfaces.RequestOptionsNetwork, sni string) *http.Transport {
	key := requestTransportCacheKey{
		vendorRef: vendorReference(p),
		network:   network,
		sni:       sni,
	}

	return requestTransportCache.getOrInit(key, func() *http.Transport {
		transport := &http.Transport{
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   100,
			IdleConnTimeout:       10 * time.Second,
			TLSHandshakeTimeout:   5 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
		if sni != "" {
			transport.TLSClientConfig = &tls.Config{ServerName: sni}
		}

		transport.DialContext = func(reqCtx context.Context, _ string, addr string) (net.Conn, error) {
			if p != nil {
				return p.DialTCP(reqCtx, formatDialAddressToURL(addr), network)
			}
			return utils.DialContext(reqCtx, network.String(), addr)
		}

		return transport
	})
}

// for all methods in commons
// if proxy is nil, fallback to system
// if proxy is not nil but it is not ready
// errors will be returned

func RequestUnsafe(ctx context.Context, p interfaces.Vendor, reqOpt *interfaces.RequestOptions) (*http.Response, []string, error) {
	if p != nil && p.Status() == interfaces.VStatusNotReady || reqOpt == nil {
		return nil, nil, errors.New("proxy is not ready")
	}

	// check request method
	if reqOpt.Method == "" {
		reqOpt.Method = http.MethodGet
	}

	// check body reader
	var reader io.Reader = nil
	if reqOpt.Reader != nil {
		reader = reqOpt.Reader
	} else if len(reqOpt.Body) > 0 {
		reader = bytes.NewBuffer(reqOpt.Body)
	}

	// build request
	req, err := http.NewRequest(reqOpt.Method, reqOpt.URL, reader)
	if err != nil {
		return nil, nil, err
	}

	// write headers and cookies
	for hkey, hval := range reqOpt.Headers {
		req.Header.Add(hkey, hval)
	}
	for ckey, cval := range reqOpt.Cookies {
		req.AddCookie(&http.Cookie{Name: ckey, Value: cval})
	}
	req = req.WithContext(ctx)

	transport := getOrInitTransport(p, reqOpt.Network, reqOpt.SNI)

	// make a list to record all redirects
	// the maximum count of redirection is 64
	redirects := []string{}
	client := http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if reqOpt.NoRedir || len(redirects) > 64 {
				return http.ErrUseLastResponse
			}

			redirects = append(redirects, req.Response.Header.Get("Location"))
			return nil
		},
	}

	// send the request
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}

	return resp, redirects, nil
}

func formatDialAddressToURL(addr string) string {
	return "http://" + addr
}

func Request(ctx context.Context, p interfaces.Vendor, reqOpt *interfaces.RequestOptions) (duration uint16, bodyBytes []byte, resp *http.Response, redirects []string) {
	var err error

	start := time.Now()
	resp, redirects, err = RequestUnsafe(ctx, p, reqOpt)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	bodyBytes, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}

	duration = uint16(time.Since(start) / time.Millisecond)
	return
}

func RequestWithRetry(p interfaces.Vendor, retry int, timeoutMillisecond int64, reqOpt *interfaces.RequestOptions) ([]byte, *http.Response, []string) {
	var resp *http.Response = nil
	var retBody []byte = nil
	var redirects = []string{}

	for i := 0; resp == nil && i < structs.WithIn(retry, 1, 10); i += 1 {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMillisecond)*time.Millisecond)
		_, retBody, resp, redirects = Request(ctx, p, reqOpt)
		cancel()
	}

	return retBody, resp, redirects
}

func NetCat(ctx context.Context, p interfaces.Vendor, addr string, data []byte, network interfaces.RequestOptionsNetwork) ([]byte, error) {
	var conn net.Conn = nil
	err := fmt.Errorf("proxy is not ready")
	if p != nil {
		if p.Status() == interfaces.VStatusOperational {
			conn, err = p.DialTCP(ctx, addr, network)
		}
	} else {
		conn, err = utils.DialContext(ctx, network.String(), addr)
	}

	if err != nil {
		return nil, err
	}

	if conn == nil {
		return nil, fmt.Errorf("connection is nil")
	}

	defer func(conn net.Conn) {
		_ = conn.Close()
	}(conn)

	if ctxTimeout, ok := ctx.Deadline(); ok {
		if err := conn.SetWriteDeadline(ctxTimeout); err != nil {
			return nil, fmt.Errorf("failed to set write deadline: %w", err)
		}
	}

	if _, err := conn.Write(data); err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return nil, fmt.Errorf("write timeout: %w", err)
		}
		return nil, err
	}

	var buf bytes.Buffer

	if ctxTimeout, ok := ctx.Deadline(); ok {
		if err := conn.SetReadDeadline(ctxTimeout); err != nil {
			return nil, fmt.Errorf("failed to set read deadline: %w", err)
		}
	}

	if _, err := io.Copy(&buf, conn); err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return buf.Bytes(), nil
		}
		// Some transports (e.g. AnyTLS) report a peer-initiated close as
		// net.ErrClosed instead of io.EOF. Everything the peer sent has
		// already been read, so treat it as a normal end of stream.
		if buf.Len() > 0 && errors.Is(err, net.ErrClosed) {
			return buf.Bytes(), nil
		}
		return nil, err
	}

	return buf.Bytes(), nil
}

func NetCatWithRetry(p interfaces.Vendor, retry int, timeoutMillisecond int64, addr string, data []byte, network interfaces.RequestOptionsNetwork) ([]byte, error) {
	var retBody []byte = nil
	var err = fmt.Errorf("request not send")

	for i := 0; err != nil && i < structs.WithIn(retry, 1, 10); i += 1 {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMillisecond)*time.Millisecond)
		retBody, err = NetCat(ctx, p, addr, data, network)
		cancel()
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
		}
	}

	return retBody, err
}
