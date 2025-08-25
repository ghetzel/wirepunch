package main

import (
	"fmt"
	"net/netip"

	"github.com/ghetzel/go-stockutil/log"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type WireguardConfig struct {
	PrivateKey string
	PublicKey  string
	AllowedIPs string
	Endpoint   string
	Port       int
}

type Wireguard struct {
	config WireguardConfig
}

func (w *Wireguard) GenerateTUN(localAddresses []netip.Addr, dnsAddresses []netip.Addr) (tun.Device, *netstack.Net, error) {
	var mtu *int

	if mtu == nil {
		mtu = &DefaultMTU
	}

	return netstack.CreateNetTUN(
		localAddresses,
		dnsAddresses,
		*mtu,
	)
}

func (w *Wireguard) CreateDevice(tunDevice tun.Device, logLevel int) (*device.Device, error) {
	dev := device.NewDevice(
		tunDevice,
		conn.NewDefaultBind(),
		&device.Logger{
			Verbosef: logVerbosef,
			Errorf:   logErrorf,
		},
	)
	if dev == nil {
		return nil, fmt.Errorf("failed to create device")
	}
	return dev, nil
}

func logVerbosef(format string, args ...any) {
	log.Debugf(format, args...)
}

func logErrorf(format string, args ...any) {
	log.Errorf(format, args...)
}
