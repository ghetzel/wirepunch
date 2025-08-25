package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/ghetzel/go-stockutil/log"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

var DefaultMTU int = 1500
var DefaultProxyAddress = `127.0.0.1:1080`
var DefaultDNS1 = netip.MustParseAddr(`1.1.1.1`)

type Peer struct {
	EndpointAddress string
	LocalAddresses  []string
	DNSAddresses    []string
	PublicKey       string
	PrivateKey      string
	AllowedIPs      []string
	CheckURL        string
	CheckTimeout    time.Duration
	wg              *Wireguard
	tun             tun.Device
	tnet            *netstack.Net
	dev             *device.Device
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
	} else if _, err := netip.ParseAddrPort(peer.EndpointAddress); err != nil {
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
	if err := peer.dev.IpcSet(strings.Join(peer.configLines(), "\n")); err == nil {
		// raise interface
		if err := peer.dev.Up(); err == nil {
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
		fmt.Sprintf("endpoint=%v", peer.EndpointAddress),
	}
}

func (peer *Peer) validate() error {
	// client := http.Client{
	// 	Timeout: 30 * time.Second,
	// 	Transport: &http.Transport{
	// 		DialContext:     tnet.DialContext,
	// 		TLSClientConfig: &tls.Config{},
	// 	},
	// }

	// resp, err := client.Get(executil.Env(`BF_CHECK_URL`, `https://api.ipify.org?format=json`))
	// if err != nil {
	// 	log.Panic(err)
	// }
	// body, err := io.ReadAll(resp.Body)
	// if err != nil {
	// 	log.Panic(err)
	// }
	// fmt.Printf("Connected to remote host! Using IP address for proxy: %s\n", string(body))

	return nil
}

func (peer *Peer) RunProxy(address string) error {
	if err := peer.init(); err != nil {
		return err
	}

	var handler = &proxy{
		Tunnel: peer.tnet,
	}

	if address == `` {
		address = DefaultProxyAddress
	}

	if _, err := netip.ParseAddrPort(address); err != nil {
		return fmt.Errorf("bad proxy address %q: %v", address, err)
	}

	log.Infof("Starting HTTP proxy server on %v", address)

	return http.ListenAndServe(address, handler)
}

func base64ToHex(base64Key string) string {
	decodedKey, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		log.Panic("Failed to decode base64 key:", err)
	}
	hexKey := hex.EncodeToString(decodedKey)
	return hexKey
}
