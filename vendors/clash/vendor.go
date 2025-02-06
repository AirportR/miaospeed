package clash

import (
	"context"
	"fmt"
	"github.com/airportr/miaospeed/utils"
	"github.com/metacubex/mihomo/component/resolver"
	"net"
	"strings"
	"time"

	"github.com/airportr/miaospeed/interfaces"
	"github.com/metacubex/mihomo/constant"
)

type Clash struct {
	proxy constant.Proxy
}

func setupIPv6() {
	if utils.GCFG.EnableIPv6 {
		if resolver.DisableIPv6 {
			resolver.DisableIPv6 = false
		}
	}
}

func (c *Clash) Proxy() constant.Proxy {
	return c.proxy
}

func (c *Clash) Type() interfaces.VendorType {
	return interfaces.VendorClash
}

func (c *Clash) Status() interfaces.VendorStatus {
	if c == nil || c.proxy == nil {
		return interfaces.VStatusNotReady
	}

	return interfaces.VStatusOperational
}

func (c *Clash) Build(proxyName string, proxyInfo string) interfaces.Vendor {
	if c == nil {
		c = &Clash{}
	}
	c.proxy = extractFirstProxy(proxyName, proxyInfo)
	return c
}

func (c *Clash) DialTCP(ctx context.Context, url string, network interfaces.RequestOptionsNetwork) (net.Conn, error) {
	if c == nil || c.proxy == nil {
		return nil, fmt.Errorf("should call Build() before run")
	}
	setupIPv6()
	timeoutCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		addr, err := urlToMetadata(url, constant.TCP)
		if err != nil {
			ch <- result{nil, fmt.Errorf("cannot build tcp context: %v", err)}
		}
		conn, err := c.proxy.DialContext(timeoutCtx, &addr)
		if err != nil && !strings.Contains(err.Error(), "timeout") && !strings.Contains(err.Error(), "no such host") {
			utils.DLogf("cannot dialTCP: %s | proxy=%s | vendor=Clash | err=%s", url, c.proxy.Name(), err.Error())
		}
		ch <- result{conn, err}
	}()
	select {
	case res := <-ch:
		return res.conn, res.err
	case <-timeoutCtx.Done():
		return nil, fmt.Errorf("dialTCP timeout after 10 seconds: %w", timeoutCtx.Err())
	}
}

func (c *Clash) DialUDP(ctx context.Context, url string) (net.PacketConn, error) {
	if c == nil || c.proxy == nil {
		return nil, fmt.Errorf("should call Build() before run")
	}
	setupIPv6()
	timeoutCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	type result struct {
		conn net.PacketConn
		err  error
	}
	ch := make(chan result, 1)

	go func() {
		addr, err := urlToMetadata(url, constant.UDP)
		if err != nil {
			ch <- result{nil, fmt.Errorf("cannot build udp context: %w", err)}
			return
		}

		conn, err := c.proxy.ListenPacketContext(timeoutCtx, &addr)
		if err != nil && !strings.Contains(err.Error(), "timeout") && !strings.Contains(err.Error(), "no such host") {
			utils.DLogf("cannot dialUDP: %s | proxy=%s | vendor=Clash | err=%s", url, c.proxy.Name(), err.Error())
		}
		ch <- result{conn, err}
	}()

	select {
	case res := <-ch:
		return res.conn, res.err
	case <-timeoutCtx.Done():
		return nil, fmt.Errorf("dialUDP timeout after 5 seconds: %w", timeoutCtx.Err())
	}
}
func (c *Clash) ProxyInfo() interfaces.ProxyInfo {
	if c == nil || c.proxy == nil {
		return interfaces.ProxyInfo{}
	}

	return interfaces.ProxyInfo{
		Name:    c.proxy.Name(),
		Address: c.proxy.Addr(),
		Type:    interfaces.Parse(c.proxy.Type().String()),
	}
}
