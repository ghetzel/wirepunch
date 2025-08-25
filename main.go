package main

import (
	"os"
	"time"

	"github.com/ghetzel/go-stockutil/log"

	"github.com/ghetzel/cli"
)

func main() {
	var app = cli.NewApp()
	app.Name = `wirepunch`
	app.Usage = `Usermode Wireguard HTTP & SOCKS5 proxy`
	app.Version = ApplicationVersion
	app.EnableBashCompletion = true

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   `http-proxy`,
			Usage:  `Address the HTTP proxy server should listen on`,
			Value:  DefaultProxyHTTPAddress,
			EnvVar: `WP_PROXY_HTTP_ADDRESS`,
		},
		cli.StringFlag{
			Name:   `log-level, L`,
			Usage:  `Level of log output verbosity`,
			Value:  `info`,
			EnvVar: `LOGLEVEL`,
		},
		cli.StringFlag{
			Name:   `public-key, k`,
			Usage:  `Public key for the local Wireguard peer`,
			EnvVar: `WP_PUBLIC_KEY`,
		},
		cli.StringFlag{
			Name:   `private-key, K`,
			Usage:  `Private key for the local Wireguard peer`,
			EnvVar: `WP_PRIVATE_KEY`,
		},
		cli.StringFlag{
			Name:   `address, a`,
			Usage:  `Local Wireguard peer address`,
			EnvVar: `WP_ADDRESS`,
		},
		cli.StringFlag{
			Name:   `endpoint, e`,
			Usage:  `Wireguard remote peer endpoint address [address:port]`,
			EnvVar: `WP_ENDPOINT`,
		},
		cli.StringFlag{
			Name:   `dns-server, D`,
			Usage:  `DNS server address to use for hostname lookups`,
			EnvVar: `WP_DNS_SERVER`,
		},
		cli.StringFlag{
			Name:   `check-url, U`,
			Usage:  `URL to perform an HTTP GET request at to verify the connection is active on startup`,
			EnvVar: `WP_CHECK_URL`,
		},
		cli.DurationFlag{
			Name:   `check-url-timeout, T`,
			Usage:  `Timeout when performing the initial URL check`,
			EnvVar: `WP_CHECK_TIMEOUT`,
			Value:  30 * time.Second,
		},
	}

	app.Action = func(c *cli.Context) {
		var peer = &Peer{
			EndpointAddress: c.String(`endpoint`),
			LocalAddresses: []string{
				c.String(`address`),
			},
			DNSAddresses: []string{
				c.String(`dns-server`),
			},
			PublicKey:    c.String(`public-key`),
			PrivateKey:   c.String(`private-key`),
			CheckURL:     c.String(`check-url`),
			CheckTimeout: c.Duration(`check-url-timeout`),
		}

		log.FatalIf(peer.RunProxy(c.String(`http-proxy`)))
	}

	app.Run(os.Args)
}
