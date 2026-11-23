package tor

import (
	"context"
	"maps"
	"net"
	"os"
	"path/filepath"
	"slices"
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
	ctx                   context.Context
	logger                logger.ContextLogger
	dialer                N.Dialer
	startConf             *tor.StartConf
	geoIPFile             string
	geoIP6File            string
	dataDirectoryProvider DataDirectoryProvider
	dataDirectoryKey      string
	bridges               []*bridge
	exitCountries         []string
	options               map[string]string
	access                sync.Mutex
	scope                 *adapter.Scope
	proxy                 *proxybridge.Bridge
	transport             *transportListener
	instance              *tor.Tor
	releaseDataDirectory  func()
	events                chan control.Event
	eventsDone            chan struct{}
	socksClient           *socks.Client
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.TorOutboundOptions) (adapter.Outbound, error) {
	err := adapter.CheckSecurityFeature(ctx, "Tor outbound")
	if err != nil {
		return nil, err
	}
	bridges, err := parseBridges(options.Bridges)
	if err != nil {
		return nil, err
	}
	exitCountries, err := parseExitCountries(options.ExitCountries)
	if err != nil {
		return nil, err
	}
	for key := range options.Options {
		switch strings.ToLower(key) {
		case "bridge", "usebridges", "clienttransportplugin":
			if len(bridges) > 0 {
				return nil, E.New("torrc option ", key, " conflicts with bridges")
			}
		case "exitnodes":
			if len(exitCountries) > 0 {
				return nil, E.New("torrc option ", key, " conflicts with exit_countries")
			}
		}
	}
	var startConf tor.StartConf
	dataDirectoryProvider := service.FromContext[DataDirectoryProvider](ctx)
	if dataDirectoryProvider == nil {
		startConf.DataDir = os.ExpandEnv(options.DataDirectory)
	}
	if startConf.DataDir != "" {
		startConf.DataDir = filemanager.BasePath(ctx, startConf.DataDir)
		torrcFile := filepath.Join(startConf.DataDir, "torrc")
		torrcInfo, err := filemanager.Stat(ctx, torrcFile)
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		} else if err == nil && torrcInfo.IsDir() {
			return nil, E.New("Tor configuration path is a directory: ", torrcFile)
		}
		startConf.TorrcFile = torrcFile
	}
	startConf.TempDataDirBase = filemanager.TempPath(ctx)
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
	// meek, webtunnel and snowflake reach their fronts and brokers by domain name
	remoteIsDomain := common.Any(bridges, func(it *bridge) bool {
		return it.transport != "" && it.transport != "obfs4"
	})
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, remoteIsDomain)
	if err != nil {
		return nil, err
	}
	var directoryKey string
	if dataDirectoryProvider != nil {
		directoryKey = dataDirectoryKey(bridges, exitCountries)
	}
	return &Outbound{
		Adapter:               outbound.NewAdapterWithDialerOptions(C.TypeTor, tag, []string{N.NetworkTCP}, options.DialerOptions),
		ctx:                   ctx,
		logger:                logger,
		dialer:                outboundDialer,
		startConf:             &startConf,
		geoIPFile:             resolvePath(ctx, options.GeoIPFile),
		geoIP6File:            resolvePath(ctx, options.GeoIP6File),
		dataDirectoryProvider: dataDirectoryProvider,
		dataDirectoryKey:      directoryKey,
		bridges:               bridges,
		exitCountries:         exitCountries,
		options:               options.Options,
	}, nil
}

func resolvePath(ctx context.Context, path string) string {
	path = os.ExpandEnv(path)
	if path == "" {
		return ""
	}
	return filemanager.BasePath(ctx, path)
}

func (t *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	switch stage {
	case adapter.StartStateInitialize:
		if t.startConf.DataDir == "" {
			return nil
		}
		return t.prepareDataDirectory(t.startConf.DataDir)
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

func (t *Outbound) prepareDataDirectory(dataDirectory string) error {
	err := filemanager.MkdirAll(t.ctx, dataDirectory, 0o755)
	if err != nil {
		return err
	}
	torrcFile := filepath.Join(dataDirectory, "torrc")
	torrcInfo, err := filemanager.Stat(t.ctx, torrcFile)
	if os.IsNotExist(err) {
		return filemanager.WriteFile(t.ctx, torrcFile, []byte(""), 0o600)
	} else if err != nil {
		return err
	} else if torrcInfo.IsDir() {
		return E.New("Tor configuration path is a directory: ", torrcFile)
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
	startConf := *t.startConf
	if t.dataDirectoryProvider != nil {
		dataDirectory, release, err := t.dataDirectoryProvider.Acquire(t.dataDirectoryKey)
		if err != nil {
			return E.Cause(err, "acquire data directory")
		}
		t.releaseDataDirectory = release
		err = t.prepareDataDirectory(dataDirectory)
		if err != nil {
			return err
		}
		startConf.DataDir = dataDirectory
		startConf.TorrcFile = filepath.Join(dataDirectory, "torrc")
	}
	startConf.ExtraArgs = slices.Concat(startConf.ExtraArgs, t.geoIPArgs(startConf.DataDir))
	proxy, err := proxybridge.New(t.ctx, t.logger, "proxy", t.dialer)
	if err != nil {
		return err
	}
	err = proxy.Start()
	if err != nil {
		return err
	}
	t.proxy = proxy
	if common.Any(t.bridges, func(it *bridge) bool {
		return it.transport != ""
	}) {
		transport, err := newTransportListener(t.ctx, t.logger, t.dialer, proxy, t.bridges)
		if err != nil {
			return err
		}
		t.transport = transport
		t.logger.Trace("created pluggable transport listener at 127.0.0.1:", transport.Port())
	}
	// Not the scope context: it is canceled before cleanups run, which would kill tor before the HALT signal.
	torInstance, err := tor.Start(t.ctx, &startConf)
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
	// with the listener, every bridge goes through it and the upstream proxy only serves snowflake
	if t.transport == nil {
		err = torInstance.Control.ResetConf(
			control.NewKeyVal("Socks5Proxy", proxyPort),
			control.NewKeyVal("Socks5ProxyUsername", proxyUsername),
			control.NewKeyVal("Socks5ProxyPassword", proxyPassword),
		)
		if err != nil {
			return err
		}
	}
	// tor validates a SETCONF as a whole and replaces list options, so bridges and their plugins go in one request
	confOptions := t.confOptions()
	if len(confOptions) > 0 {
		err = torInstance.Control.SetConf(confOptions...)
		if err != nil {
			return E.Cause(err, "set tor options")
		}
	}
	if len(t.exitCountries) > 0 {
		info, err := torInstance.Control.GetInfo("ip-to-country/ipv4-available")
		if err != nil {
			return err
		}
		if len(info) != 1 || info[0].Val != "1" {
			return E.New("exit_countries requires a GeoIP file")
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

func (t *Outbound) geoIPArgs(dataDirectory string) []string {
	var args []string
	if !common.Contains(t.startConf.ExtraArgs, "--GeoIPFile") {
		geoIPPath := t.findGeoIPFile(t.geoIPFile, dataDirectory, "geoip")
		if geoIPPath != "" {
			args = append(args, "--GeoIPFile", geoIPPath)
		}
	}
	if !common.Contains(t.startConf.ExtraArgs, "--GeoIPv6File") {
		geoIP6Path := t.findGeoIPFile(t.geoIP6File, dataDirectory, "geoip6")
		if geoIP6Path != "" {
			args = append(args, "--GeoIPv6File", geoIP6Path)
		}
	}
	return args
}

func (t *Outbound) findGeoIPFile(path string, dataDirectory string, name string) string {
	candidates := []string{path}
	if dataDirectory != "" {
		candidates = append(candidates, filepath.Join(dataDirectory, name))
	}
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		info, err := filemanager.Stat(t.ctx, candidate)
		if err == nil && !info.IsDir() {
			absolutePath, _ := filepath.Abs(candidate)
			return absolutePath
		}
	}
	return ""
}

func (t *Outbound) confOptions() []*control.KeyVal {
	var confOptions []*control.KeyVal
	for _, key := range slices.Sorted(maps.Keys(t.options)) {
		switch strings.ToLower(key) {
		case "socks5proxy", "socks5proxyusername", "socks5proxypassword":
			continue
		}
		confOptions = append(confOptions, newKeyVal(key, t.options[key]))
	}
	if len(t.bridges) > 0 {
		var secret string
		if t.transport != nil {
			secret = t.transport.Secret()
			address := "127.0.0.1:" + F.ToString(t.transport.Port())
			// tor refuses one external proxy line for several transports
			for _, transport := range common.Uniq(common.Map(t.bridges, (*bridge).pluginTransport)) {
				confOptions = append(confOptions, newKeyVal("ClientTransportPlugin", transport+" socks5 "+address))
			}
		}
		for index, it := range t.bridges {
			confOptions = append(confOptions, newKeyVal("Bridge", it.torLine(secret, index)))
		}
		confOptions = append(confOptions, newKeyVal("UseBridges", "1"))
	}
	if len(t.exitCountries) > 0 {
		exitNodes := common.Map(t.exitCountries, func(it string) string {
			return "{" + it + "}"
		})
		confOptions = append(confOptions, newKeyVal("ExitNodes", strings.Join(exitNodes, ",")))
	}
	return confOptions
}

// bine sends the SETCONF line as a printf format
func newKeyVal(key string, value string) *control.KeyVal {
	return control.NewKeyVal(strings.ReplaceAll(key, "%", "%%"), strings.ReplaceAll(value, "%", "%%"))
}

func (t *Outbound) stop() error {
	err := common.Close(
		common.PtrOrNil(t.instance),
		common.PtrOrNil(t.transport),
		common.PtrOrNil(t.proxy),
	)
	// events are also relayed by control requests, so close only after tor is closed and the event loop exited
	if t.eventsDone != nil {
		<-t.eventsDone
	}
	if t.events != nil {
		close(t.events)
	}
	if t.releaseDataDirectory != nil {
		t.releaseDataDirectory()
	}
	t.proxy = nil
	t.transport = nil
	t.instance = nil
	t.releaseDataDirectory = nil
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

// Warm launches tor in the background ahead of the first connection.
func (t *Outbound) Warm() {
	go func() {
		_, err := t.prepareClient()
		if err != nil && !E.IsClosedOrCanceled(err) {
			t.logger.Error(err)
		}
	}()
}

// NewIdentity switches new streams to fresh circuits.
func (t *Outbound) NewIdentity() error {
	t.access.Lock()
	defer t.access.Unlock()
	if t.instance == nil {
		return E.New("tor is not running")
	}
	return t.instance.Control.Signal("NEWNYM")
}
