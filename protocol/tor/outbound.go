package tor

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/proxybridge"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"

	"github.com/cretz/bine/control"
	"github.com/cretz/bine/process"
	"github.com/cretz/bine/tor"
	"github.com/cretz/bine/torutil"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.TorOutboundOptions](registry, C.TypeTor, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	ctx         context.Context
	logger      logger.ContextLogger
	dialer      N.Dialer
	startConf   *tor.StartConf
	options     map[string]string
	access      sync.Mutex
	scope       *adapter.Scope
	proxy       *proxybridge.Bridge
	instance    *tor.Tor
	events      chan control.Event
	eventsDone  chan struct{}
	socksClient *socks.Client
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.TorOutboundOptions) (adapter.Outbound, error) {
	err := adapter.CheckSecurityFeature(ctx, "Tor outbound")
	if err != nil {
		return nil, err
	}
	var startConf tor.StartConf
	startConf.DataDir = os.ExpandEnv(options.DataDirectory)
	if startConf.DataDir != "" {
		startConf.DataDir = filemanager.BasePath(ctx, startConf.DataDir)
	}
	startConf.TempDataDirBase = filemanager.TempPath(ctx)
	if startConf.DataDir != "" {
		dataDirAbs, _ := filepath.Abs(startConf.DataDir)
		geoIPPath := filepath.Join(dataDirAbs, "geoip")
		geoIPInfo, err := filemanager.Stat(ctx, geoIPPath)
		if err == nil && !geoIPInfo.IsDir() && !common.Contains(options.ExtraArgs, "--GeoIPFile") {
			options.ExtraArgs = append(options.ExtraArgs, "--GeoIPFile", geoIPPath)
		}
		geoIP6Path := filepath.Join(dataDirAbs, "geoip6")
		geoIP6Info, err := filemanager.Stat(ctx, geoIP6Path)
		if err == nil && !geoIP6Info.IsDir() && !common.Contains(options.ExtraArgs, "--GeoIPv6File") {
			options.ExtraArgs = append(options.ExtraArgs, "--GeoIPv6File", geoIP6Path)
		}
		torrcFile := filepath.Join(startConf.DataDir, "torrc")
		torrcInfo, err := filemanager.Stat(ctx, torrcFile)
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		} else if err == nil && torrcInfo.IsDir() {
			return nil, E.New("Tor configuration path is a directory: ", torrcFile)
		}
		startConf.TorrcFile = torrcFile
	}
	// tor exits if this process dies before the controller takes ownership
	options.ExtraArgs = append(options.ExtraArgs, "--__OwningControllerProcess", F.ToString(os.Getpid()))
	startConf.ExtraArgs = options.ExtraArgs
	processCreator := service.FromContext[ProcessCreator](ctx)
	if processCreator != nil {
		executablePath := options.ExecutablePath
		if executablePath == "" {
			executablePath = "tor"
		}
		startConf.ProcessCreator = processCreatorFunc(func(ctx context.Context, args ...string) (process.Process, error) {
			return processCreator.NewProcess(ctx, executablePath, args...)
		})
		startConf.UseEmbeddedControlConn = false
	} else if options.ExecutablePath != "" {
		startConf.ExePath = options.ExecutablePath
		startConf.ProcessCreator = nil
		startConf.UseEmbeddedControlConn = false
	}
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, false)
	if err != nil {
		return nil, err
	}
	return &Outbound{
		Adapter:   outbound.NewAdapterWithDialerOptions(C.TypeTor, tag, []string{N.NetworkTCP}, options.DialerOptions),
		ctx:       ctx,
		logger:    logger,
		dialer:    outboundDialer,
		startConf: &startConf,
		options:   options.Options,
	}, nil
}

func (t *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	switch stage {
	case adapter.StartStateInitialize:
		if t.startConf.DataDir == "" {
			return nil
		}
		err := filemanager.MkdirAll(t.ctx, t.startConf.DataDir, 0o755)
		if err != nil {
			return err
		}
		torrcInfo, err := filemanager.Stat(t.ctx, t.startConf.TorrcFile)
		if os.IsNotExist(err) {
			err = filemanager.WriteFile(t.ctx, t.startConf.TorrcFile, []byte(""), 0o600)
			if err != nil {
				return err
			}
		} else if err != nil {
			return err
		} else if torrcInfo.IsDir() {
			return E.New("Tor configuration path is a directory: ", t.startConf.TorrcFile)
		}
	case adapter.StartStateStart:
		// Registered before the scope is published: a launch can only happen while this cleanup is pending.
		scope.Add(func() error {
			t.access.Lock()
			defer t.access.Unlock()
			return t.stop()
		})
		t.access.Lock()
		t.scope = scope
		t.access.Unlock()
	}
	return nil
}

var torEvents = []control.EventCode{
	control.EventCodeLogErr,
	control.EventCodeLogInfo,
	control.EventCodeLogNotice,
	control.EventCodeLogWarn,
	control.EventCodeStatusClient,
}

func (t *Outbound) prepareClient() (*socks.Client, error) {
	t.access.Lock()
	defer t.access.Unlock()
	if t.socksClient != nil {
		return t.socksClient, nil
	}
	if t.scope == nil {
		return nil, E.New("Tor outbound is not started")
	}
	if t.scope.Context().Err() != nil {
		return nil, net.ErrClosed
	}
	err := t.start()
	if err != nil {
		t.stop()
		return nil, E.Cause(err, "start tor")
	}
	return t.socksClient, nil
}

func (t *Outbound) start() error {
	proxy, err := proxybridge.New(t.ctx, t.logger, "proxy", t.dialer)
	if err != nil {
		return err
	}
	err = proxy.Start()
	if err != nil {
		return err
	}
	t.proxy = proxy
	// Not the scope context: it is canceled before cleanups run, which would kill tor before the HALT signal.
	torInstance, err := tor.Start(t.ctx, t.startConf)
	if err != nil {
		return E.New(strings.ToLower(err.Error()))
	}
	t.instance = torInstance
	err = torInstance.Control.TakeOwnership()
	if err != nil {
		return E.Cause(err, "take ownership")
	}
	err = torInstance.Control.ResetConf(control.NewKeyVal("__OwningControllerProcess", ""))
	if err != nil {
		return E.Cause(err, "reset __OwningControllerProcess")
	}
	t.events = make(chan control.Event, 8)
	go t.recvLoop(t.events)
	err = torInstance.Control.AddEventListener(t.events, torEvents...)
	if err != nil {
		return err
	}
	proxyPort := "127.0.0.1:" + F.ToString(proxy.Port())
	proxyUsername := proxy.Username()
	proxyPassword := proxy.Password()
	t.logger.Trace("created upstream proxy at ", proxyPort)
	t.logger.Trace("upstream proxy username ", proxyUsername)
	t.logger.Trace("upstream proxy password ", proxyPassword)
	confOptions := []*control.KeyVal{
		control.NewKeyVal("Socks5Proxy", proxyPort),
		control.NewKeyVal("Socks5ProxyUsername", proxyUsername),
		control.NewKeyVal("Socks5ProxyPassword", proxyPassword),
	}
	err = torInstance.Control.ResetConf(confOptions...)
	if err != nil {
		return err
	}
	if len(t.options) > 0 {
		for key, value := range t.options {
			switch key {
			case "Socks5Proxy",
				"Socks5ProxyUsername",
				"Socks5ProxyPassword":
				continue
			}
			err = torInstance.Control.SetConf(control.NewKeyVal(key, value))
			if err != nil {
				return E.Cause(err, "set ", key, "=", value)
			}
		}
	}
	// tor holds SOCKS streams until circuits are built, so bootstrap is not awaited
	err = torInstance.EnableNetwork(t.ctx, false)
	if err != nil {
		return err
	}
	info, err := torInstance.Control.GetInfo("net/listeners/socks")
	if err != nil {
		return err
	}
	if len(info) != 1 || info[0].Key != "net/listeners/socks" {
		return E.New("get socks proxy address")
	}
	t.logger.Trace("obtained tor socks5 address ", info[0].Val)
	// TODO: set password for tor socks5 server if supported
	t.socksClient = socks.NewClient(N.SystemDialer, M.ParseSocksaddr(info[0].Val), socks.Version5, "", "")
	// started last: HandleNextEvent holds the read lock that every control request waits on
	t.eventsDone = make(chan struct{})
	go t.handleEvents(torInstance.Control, t.eventsDone)
	return nil
}

func (t *Outbound) stop() error {
	err := common.Close(
		common.PtrOrNil(t.instance),
		common.PtrOrNil(t.proxy),
	)
	// events are also relayed by control requests, so close only after tor is closed and the event loop exited
	if t.eventsDone != nil {
		<-t.eventsDone
	}
	if t.events != nil {
		close(t.events)
	}
	t.proxy = nil
	t.instance = nil
	t.events = nil
	t.eventsDone = nil
	t.socksClient = nil
	return err
}

func (t *Outbound) handleEvents(conn *control.Conn, done chan struct{}) {
	defer close(done)
	for {
		err := conn.HandleNextEvent()
		if err != nil {
			return
		}
	}
}

func (t *Outbound) recvLoop(events <-chan control.Event) {
	for rawEvent := range events {
		switch event := rawEvent.(type) {
		case *control.LogEvent:
			event.Raw = strings.ToLower(event.Raw)
			switch event.Severity {
			case control.EventCodeLogDebug, control.EventCodeLogInfo:
				t.logger.Trace(event.Raw)
			case control.EventCodeLogNotice:
				if strings.Contains(event.Raw, "disablenetwork") || strings.Contains(event.Raw, "socks listener") || strings.Contains(event.Raw, "bootstrapped") {
					t.logger.Trace(event.Raw)
					continue
				}
				t.logger.Info(event.Raw)
			case control.EventCodeLogWarn:
				if strings.Contains(event.Raw, "problem bootstrapping") {
					t.logger.Trace(event.Raw)
					continue
				}
				t.logger.Warn(event.Raw)
			case control.EventCodeLogErr:
				t.logger.Error(event.Raw)
			}
		case *control.StatusEvent:
			if event.Action != "BOOTSTRAP" {
				continue
			}
			arguments := parseStatusArguments(event.Raw)
			progress := arguments["PROGRESS"]
			switch event.Severity {
			case "NOTICE":
				t.logger.Info("bootstrapped ", progress, "%: ", arguments["SUMMARY"])
			case "WARN":
				// control-spec: a problem with RECOMMENDATION=ignore is logged without alerting the user
				if arguments["RECOMMENDATION"] == "ignore" {
					t.logger.Debug("bootstrap problem at ", progress, "%: ", arguments["WARNING"], " (", arguments["REASON"], ")")
				} else {
					t.logger.Warn("bootstrap problem at ", progress, "%: ", arguments["WARNING"], " (", arguments["REASON"], ")")
				}
			case "ERR":
				t.logger.Error("bootstrap failed at ", progress, "%: ", arguments["WARNING"], " (", arguments["REASON"], ")")
			}
		}
	}
}

// bine's StatusEvent.Arguments splits on every space, breaking quoted values such as SUMMARY.
func parseStatusArguments(raw string) map[string]string {
	arguments := make(map[string]string)
	var quoted, escaped bool
	start := 0
	for index := 0; index <= len(raw); index++ {
		if index < len(raw) {
			switch {
			case escaped:
				escaped = false
				continue
			case raw[index] == '\\':
				escaped = quoted
				continue
			case raw[index] == '"':
				quoted = !quoted
				continue
			case quoted || raw[index] != ' ':
				continue
			}
		}
		key, value, loaded := strings.Cut(raw[start:index], "=")
		if loaded {
			arguments[key], _ = torutil.UnescapeSimpleQuotedStringIfNeeded(value)
		}
		start = index + 1
	}
	return arguments
}

func (t *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	t.logger.InfoContext(ctx, "outbound connection to ", destination)
	socksClient, err := t.prepareClient()
	if err != nil {
		return nil, err
	}
	return socksClient.DialContext(ctx, network, destination)
}

func (t *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}
