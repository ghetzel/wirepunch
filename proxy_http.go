package main

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ghetzel/go-stockutil/log"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

var hopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func delHopHeaders(header http.Header) {
	for _, h := range hopHeaders {
		header.Del(h)
	}
}

func appendHostToXForwardHeader(header http.Header, host string) {
	if prior, ok := header["X-Forwarded-For"]; ok {
		host = strings.Join(prior, ", ") + ", " + host
	}
	header.Set("X-Forwarded-For", host)
}

type ProxyHTTP struct {
	Tunnel             *netstack.Net
	Timeout            time.Duration
	InsecureSkipVerify bool
}

func (p *ProxyHTTP) ServeHTTP(wr http.ResponseWriter, req *http.Request) {
	log.Infof(">> [%s] %s %s", req.RemoteAddr, req.Method, req.URL.Host)

	if req.Method == http.MethodConnect {
		p.handleCONNECT(wr, req)
		return
	}

	if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
		http.Error(wr, "unsupported protocol scheme "+req.URL.Scheme, http.StatusBadRequest)
		return
	}

	var client = &http.Client{
		Timeout: p.Timeout,
		Transport: &http.Transport{
			DialContext: p.Tunnel.DialContext,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: p.InsecureSkipVerify,
			},
		},
	}

	req.RequestURI = ""
	delHopHeaders(req.Header)

	if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		appendHostToXForwardHeader(req.Header, clientIP)
	}

	resp, err := client.Do(req)
	if err != nil {
		http.Error(wr, "Server Error", http.StatusInternalServerError)
		log.Errorf("proxy error: %v", err)
		return
	}
	defer resp.Body.Close()

	log.Infof("<< [%s] %s", req.RemoteAddr, resp.Status)

	delHopHeaders(resp.Header)
	copyHeader(wr.Header(), resp.Header)
	wr.WriteHeader(resp.StatusCode)
	io.Copy(wr, resp.Body)
}

func (p *ProxyHTTP) handleCONNECT(wr http.ResponseWriter, req *http.Request) {
	targetConn, err := p.Tunnel.Dial("tcp", req.Host)
	if err != nil {
		http.Error(wr, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer targetConn.Close()

	hijacker, ok := wr.(http.Hijacker)
	if !ok {
		http.Error(wr, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(wr, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	go io.Copy(targetConn, clientConn)
	io.Copy(clientConn, targetConn)
}
