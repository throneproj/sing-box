package dnstt

import (
	"context"
	"net/url"
	"time"

	"github.com/sagernet/sing-box/common/badhttp"
	"github.com/sagernet/sing-box/common/systemdns"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/dnstt"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/net/http2"
)

func newClientOptions(ctx context.Context, logger logger.ContextLogger, dialer N.Dialer, options option.DNSTTOutboundOptions) (dnstt.ClientOptions, *systemdns.Source, error) {
	clientOptions := dnstt.ClientOptions{
		Context:           ctx,
		Logger:            logger,
		Dialer:            dialer,
		Mode:              options.Mode,
		DNSTTCompat:       options.DNSTTCompat,
		Domain:            options.Domain,
		PublicKey:         options.PublicKey,
		RecordType:        options.RecordType,
		ClientIDSize:      options.ClientIDSize,
		MaxQNameLen:       options.MaxQNameLen,
		RPS:               options.RPS,
		IdleTimeout:       time.Duration(options.IdleTimeout),
		KeepAliveInterval: time.Duration(options.KeepAliveInterval),
		HandshakeTimeout:  time.Duration(options.HandshakeTimeout),
		ResolverStrategy:  options.ResolverStrategy,
	}
	var hasSystem bool
	for index, resolverOptions := range options.Resolvers {
		resolver, err := newResolverOptions(ctx, logger, resolverOptions)
		if err != nil {
			return dnstt.ClientOptions{}, nil, E.Cause(err, "resolvers[", index, "]")
		}
		if resolver.Type == dnstt.ResolverTypeSystem {
			hasSystem = true
		}
		clientOptions.Resolvers = append(clientOptions.Resolvers, resolver)
	}
	if !hasSystem {
		return clientOptions, nil, nil
	}
	system, err := systemdns.NewSource(ctx)
	if err != nil {
		return dnstt.ClientOptions{}, nil, err
	}
	clientOptions.SystemResolvers = system.Servers
	return clientOptions, system, nil
}

func newResolverOptions(ctx context.Context, logger logger.ContextLogger, options option.DNSTTResolverOptions) (dnstt.ResolverOptions, error) {
	resolver := dnstt.ResolverOptions{
		Type:        options.Type,
		TCPFallback: options.TCPFallback,
	}
	if resolver.Type == "" {
		resolver.Type = dnstt.ResolverTypeUDP
	}
	if resolver.Type == dnstt.ResolverTypeSystem {
		return resolver, nil
	}
	if options.Server == "" {
		return dnstt.ResolverOptions{}, E.New("missing server")
	}
	resolver.Server = options.ServerOptions.Build()
	if resolver.Server.Port == 0 {
		switch resolver.Type {
		case dnstt.ResolverTypeTLS:
			resolver.Server.Port = 853
		case dnstt.ResolverTypeHTTPS:
			resolver.Server.Port = 443
		default:
			resolver.Server.Port = 53
		}
	}
	if resolver.Type != dnstt.ResolverTypeTLS && resolver.Type != dnstt.ResolverTypeHTTPS {
		return resolver, nil
	}
	tlsOptions := common.PtrValueOrDefault(options.TLS)
	tlsOptions.Enabled = true
	tlsConfig, err := tls.NewClient(ctx, logger, options.Server, tlsOptions)
	if err != nil {
		return dnstt.ResolverOptions{}, err
	}
	resolver.TLSConfig = tlsConfig
	if resolver.Type == dnstt.ResolverTypeTLS {
		return resolver, nil
	}
	if len(tlsConfig.NextProtos()) == 0 {
		tlsConfig.SetNextProtos([]string{http2.NextProtoTLS, "http/1.1"})
	}
	host := tlsConfig.ServerName()
	if host == "" {
		host = options.Server
	}
	destinationAddress := M.ParseSocksaddrHostPort(host, resolver.Server.Port)
	destinationURL := url.URL{Scheme: "https"}
	if resolver.Server.Port != 443 {
		destinationURL.Host = destinationAddress.String()
	} else if destinationAddress.IsIPv6() {
		destinationURL.Host = "[" + destinationAddress.AddrString() + "]"
	} else {
		destinationURL.Host = destinationAddress.AddrString()
	}
	path := options.Path
	if path == "" {
		path = "/dns-query"
	}
	err = badhttp.URLSetPath(&destinationURL, path)
	if err != nil {
		return dnstt.ResolverOptions{}, err
	}
	resolver.URL = destinationURL.String()
	return resolver, nil
}
