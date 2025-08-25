package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/ghetzel/go-stockutil/log"
	"github.com/ghetzel/go-stockutil/typeutil"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

var DefaultMTU int = 1500
var DefaultProxyHTTPAddress = `127.0.0.1:8080`
var DefaultProxySOCKS5Address = `127.0.0.1:1080`
var DefaultDNS1 = netip.MustParseAddr(`1.1.1.1`)
var DefaultHostLookupTimeout = 10 * time.Second

type Peer struct {
	EndpointAddress  string
	LocalAddresses   []string
	DNSAddresses     []string
	PublicKey        string
	PrivateKey       string
	AllowedIPs       []string
	CheckURL         string
	CheckTimeout     time.Duration
	RetryDelay       time.Duration
	ProxyHTTPAddress string
	wg               *Wireguard
	tun              tun.Device
	tnet             *netstack.Net
	dev              *device.Device
	endpointAddr     string
	endpointPort     int
}

func (peer *Peer) reset() {
	if peer.dev != nil {
		peer.dev.Close()
	}

	peer.wg = nil
	peer.tun = nil
	peer.tnet = nil
	peer.dev = nil
	peer.endpointAddr = ``
	peer.endpointPort = 0
}

func (peer *Peer) init() error {
	if peer.wg != nil {
		return nil
	}

	// validate basic fields
	if peer.PublicKey == `` {
		return fmt.Errorf("must provide a Wireguard public key")
	} else if peer.PrivateKey == `` {
		return fmt.Errorf("must provide a Wireguard private key")
	} else if host, port, err := net.SplitHostPort(peer.EndpointAddress); err == nil {
		var ctx, cancel = context.WithTimeout(context.Background(), DefaultHostLookupTimeout)
		defer cancel()

		if ips, err := net.DefaultResolver.LookupIP(ctx, `ip4`, host); err == nil {
			if len(ips) > 0 {
				peer.endpointAddr = ips[rand.Intn(len(ips))].String()
				peer.endpointPort = typeutil.NInt(port)
			} else {
				return fmt.Errorf("bad endpoint %q: no IPs returned for host", host)
			}

			// ensure the ip:port parses
			if _, err := netip.ParseAddrPort(net.JoinHostPort(
				peer.endpointAddr,
				typeutil.String(peer.endpointPort),
			)); err != nil {
				return fmt.Errorf("bad endpoint %q: %v", peer.EndpointAddress, err)
			}
		} else {
			return fmt.Errorf("bad endpoint %q: %v", peer.EndpointAddress, err)
		}
	} else {
		return fmt.Errorf("bad endpoint %q: %v", peer.EndpointAddress, err)
	}

	if len(peer.AllowedIPs) == 0 {
		peer.AllowedIPs = []string{`0.0.0.0/0`}
	}

	var ips []netip.Addr
	var dns []netip.Addr

	// validate addresses
	for _, a := range peer.LocalAddresses {
		if a == `` {
			continue
		} else if addr, err := netip.ParseAddr(a); err == nil {
			ips = append(ips, addr)
		} else {
			return fmt.Errorf("bad peer address %q: %v", a, err)
		}
	}

	if len(ips) == 0 {
		return fmt.Errorf("must specify at least one local peer address")
	}

	// validate DNS addresses
	for _, a := range peer.DNSAddresses {
		if a == `` {
			continue
		} else if addr, err := netip.ParseAddr(a); err == nil {
			dns = append(dns, addr)
		} else {
			return fmt.Errorf("bad DNS address %q: %v", a, err)
		}
	}

	if len(dns) == 0 {
		dns = []netip.Addr{
			DefaultDNS1,
		}
	}

	peer.wg = new(Wireguard)

	// create tunnel interface
	if tun, tnet, err := peer.wg.GenerateTUN(ips, dns); err == nil {
		peer.tun = tun
		peer.tnet = tnet
	} else {
		return fmt.Errorf("cannot generate tun interface: %v", err)
	}

	// create Wireguard device
	if dev, err := peer.wg.CreateDevice(peer.tun, device.LogLevelError); err == nil {
		peer.dev = dev
	} else {
		return err
	}

	// configure Wireguard
	var lines = peer.configLines()

	for _, line := range lines {
		log.Debugf("config: %v", line)
	}

	if err := peer.dev.IpcSet(strings.Join(lines, "\n")); err == nil {
		// raise interface
		if err := peer.dev.Up(); err == nil {
			log.Noticef("wirepunch peer active %v -> [%v:%d]", peer.LocalAddresses, peer.endpointAddr, peer.endpointPort)
			return peer.validate()
		} else {
			return fmt.Errorf("cannot start Wireguard: %v", err)
		}
	} else {
		return fmt.Errorf("cannot configure Wireguard: %v", err)
	}
}

func (peer *Peer) configLines() []string {
	return []string{
		fmt.Sprintf("private_key=%v", base64ToHex(peer.PrivateKey)),
		fmt.Sprintf("public_key=%v", base64ToHex(peer.PublicKey)),
		fmt.Sprintf("allowed_ip=%v", strings.Join(peer.AllowedIPs, `,`)),
		fmt.Sprintf("endpoint=%v:%d", peer.endpointAddr, peer.endpointPort),
	}
}

func (peer *Peer) validate() error {
	if peer.CheckURL == `` || peer.CheckTimeout == 0 {
		return nil
	}

	var client = http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext:     peer.tnet.DialContext,
			TLSClientConfig: &tls.Config{},
		},
	}

	if resp, err := client.Get(peer.CheckURL); err == nil {
		if resp.StatusCode < http.StatusBadRequest {
			log.Infof("connection check passed: HTTP %v", resp.Status)
			return nil
		} else {
			return fmt.Errorf("connection check failed: HTTP %v", resp.Status)
		}
	} else {
		return fmt.Errorf("connection check failed: %v", err)
	}
}

func (peer *Peer) Up() error {

	for {
		var lasterr error

		if err := peer.init(); err == nil {
			lasterr = peer.RunProxy(peer.ProxyHTTPAddress)
		} else {
			lasterr = err
		}

		if peer.RetryDelay > 0 {
			peer.reset()

			if lasterr != nil {
				log.Errorf("peer failure: %v", lasterr)
			}

			time.Sleep(peer.RetryDelay)
		} else {
			return lasterr
		}
	}
}

func (peer *Peer) RunProxy(address string) error {
	var handler = &proxy{
		Tunnel: peer.tnet,
	}

	if address == `` {
		address = DefaultProxyHTTPAddress
	}

	if _, err := netip.ParseAddrPort(address); err != nil {
		return fmt.Errorf("bad proxy address %q: %v", address, err)
	}

	log.Infof("starting HTTP proxy server at %v", address)

	return http.ListenAndServe(address, handler)
}

func base64ToHex(base64Key string) string {
	if bin, err := base64.StdEncoding.DecodeString(base64Key); err == nil {
		return hex.EncodeToString(bin)
	} else {
		log.Panic("failed to decode base64 key:", err)
		return ``
	}
}
