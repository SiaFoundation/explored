package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/gateway"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils"
	"go.sia.tech/coreutils/chain"
	"go.sia.tech/coreutils/syncer"
	"go.sia.tech/explored/api"
	"go.sia.tech/explored/build"
	"go.sia.tech/explored/config"
	"go.sia.tech/explored/exchangerates"
	"go.sia.tech/explored/explorer"
	"go.sia.tech/explored/internal/syncerutil"
	"go.sia.tech/explored/persist/sqlite"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/yaml.v3"
	"lukechampine.com/upnp"
)

var cfg = config.Config{
	Directory: ".",
	HTTP: config.HTTP{
		Address: ":9980",
	},
	Syncer: config.Syncer{
		Address:    ":9981",
		Bootstrap:  true,
		EnableUPNP: false,
	},
	Scanner: config.Scanner{
		Threads:             10,
		Timeout:             30 * time.Second,
		MaxLastScan:         3 * time.Hour,
		MinLastAnnouncement: 365 * 24 * time.Hour,
	},
	ExchangeRates: config.ExchangeRates{
		Refresh: 3 * time.Second,
	},
	Consensus: config.Consensus{
		Network: "mainnet",
	},
	Index: config.Index{
		BatchSize: 1000,
	},
	Log: config.Log{
		Level: "info",
		StdOut: config.StdOut{
			Enabled:    true,
			Format:     "human",
			EnableANSI: runtime.GOOS != "windows",
		},
		File: config.LogFile{
			Enabled: true,
			Format:  "json",
		},
	},
}

// checkFatalError prints an error message to stderr and exits with a 1 exit code. If err is nil, this is a no-op.
func checkFatalError(context string, err error) {
	if err == nil {
		return
	}
	os.Stderr.WriteString(fmt.Sprintf("%s: %s\n", context, err))
	os.Exit(1)
}

// tryLoadConfig loads the config file specified by the EXPLORED_CONFIG_FILE. If
// the config file does not exist, it will not be loaded.
func tryLoadConfig() {
	configPath := "explored.yml"
	if str := os.Getenv("EXPLORED_CONFIG_FILE"); str != "" {
		configPath = str
	}

	// If the config file doesn't exist, don't try to load it.
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return
	}

	f, err := os.Open(configPath)
	checkFatalError("failed to open config file", err)
	defer f.Close()

	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)

	checkFatalError("failed to decode config file", dec.Decode(&cfg))
}

// jsonEncoder returns a zapcore.Encoder that encodes logs as JSON intended for
// parsing.
func jsonEncoder() zapcore.Encoder {
	cfg := zap.NewProductionEncoderConfig()
	cfg.EncodeTime = zapcore.RFC3339TimeEncoder
	cfg.TimeKey = "timestamp"
	return zapcore.NewJSONEncoder(cfg)
}

// humanEncoder returns a zapcore.Encoder that encodes logs as human-readable
// text.
func humanEncoder(showColors bool) zapcore.Encoder {
	cfg := zap.NewProductionEncoderConfig()
	cfg.EncodeTime = zapcore.RFC3339TimeEncoder
	cfg.EncodeDuration = zapcore.StringDurationEncoder

	if showColors {
		cfg.EncodeLevel = zapcore.CapitalColorLevelEncoder
	} else {
		cfg.EncodeLevel = zapcore.CapitalLevelEncoder
	}

	cfg.StacktraceKey = ""
	cfg.CallerKey = ""
	return zapcore.NewConsoleEncoder(cfg)
}

func parseLogLevel(level string) zap.AtomicLevel {
	switch level {
	case "debug":
		return zap.NewAtomicLevelAt(zap.DebugLevel)
	case "info":
		return zap.NewAtomicLevelAt(zap.InfoLevel)
	case "warn":
		return zap.NewAtomicLevelAt(zap.WarnLevel)
	case "error":
		return zap.NewAtomicLevelAt(zap.ErrorLevel)
	default:
		fmt.Printf("invalid log level %q", level)
		os.Exit(1)
	}
	panic("unreachable")
}

func forwardUPNP(ctx context.Context, addr string, log *zap.Logger) string {
	// wrapped so the context is appropriately canceled
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	d, err := upnp.Discover(ctx)
	if err != nil {
		log.Warn("WARN: couldn't discover UPnP device:", zap.Error(err))
		return ""
	}

	_, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)
	if !d.IsForwarded(uint16(port), "TCP") {
		if err := d.Forward(uint16(port), "TCP", "explored"); err != nil {
			log.Warn("WARN: couldn't forward port:", zap.Error(err))
		} else {
			log.Debug("p2p: Forwarded port", zap.Int("port", port))
		}
	}

	ip, err := d.ExternalIP()
	if err != nil {
		log.Warn("WARN: couldn't determine external IP:", zap.Error(err))
		return ""
	}
	log.Debug("p2p: External IP is", zap.String("ip", ip))
	return net.JoinHostPort(ip, portStr)
}

func runRootCmd(ctx context.Context, log *zap.Logger) error {
	var network *consensus.Network
	var genesisBlock types.Block

	switch cfg.Consensus.Network {
	case "mainnet":
		network, genesisBlock = chain.Mainnet()
		cfg.Syncer.Peers = append(cfg.Syncer.Peers, syncer.MainnetBootstrapPeers...)
	case "zen":
		network, genesisBlock = chain.TestnetZen()
		cfg.Syncer.Peers = append(cfg.Syncer.Peers, syncer.ZenBootstrapPeers...)
	case "anagami":
		network, genesisBlock = chain.TestnetAnagami()
		cfg.Syncer.Peers = append(cfg.Syncer.Peers, syncer.AnagamiBootstrapPeers...)
	default:
		log.Fatal("network must be 'mainnet', 'zen', or 'anagami'", zap.String("network", cfg.Consensus.Network))
	}

	bdb, err := coreutils.OpenBoltChainDB(filepath.Join(cfg.Directory, "consensus.db"))
	if err != nil {
		return fmt.Errorf("failed to open bolt database: %w", err)
	}
	defer bdb.Close()

	dbstore, tipState, err := chain.NewDBStore(bdb, network, genesisBlock)
	if err != nil {
		return fmt.Errorf("failed to create chain store: %w", err)
	}
	cm := chain.NewManager(dbstore, tipState)

	store, err := sqlite.OpenDatabase(filepath.Join(cfg.Directory, "explored.sqlite3"), log.Named("sqlite3"))
	if err != nil {
		return fmt.Errorf("failed to open sqlite database: %w", err)
	}
	defer store.Close()

	syncerListener, err := net.Listen("tcp", cfg.Syncer.Address)
	if err != nil {
		return fmt.Errorf("failed to create listener: %w", err)
	}
	defer syncerListener.Close()

	httpListener, err := net.Listen("tcp", cfg.HTTP.Address)
	if err != nil {
		return fmt.Errorf("failed to create listener: %w", err)
	}
	defer httpListener.Close()

	syncerAddr := syncerListener.Addr().String()
	if cfg.Syncer.EnableUPNP {
		remoteIP := forwardUPNP(ctx, cfg.Syncer.Address, log)
		if remoteIP != "" {
			syncerAddr = remoteIP
		}
	}

	// peers will reject us if our hostname is empty or unspecified, so use loopback
	host, port, _ := net.SplitHostPort(syncerAddr)
	if ip := net.ParseIP(host); ip == nil || ip.IsUnspecified() {
		syncerAddr = net.JoinHostPort("127.0.0.1", port)
	}

	ps, err := syncerutil.NewJSONPeerStore(filepath.Join(cfg.Directory, "peers.json"))
	if err != nil {
		return fmt.Errorf("failed to open peer store: %w", err)
	}
	for _, peer := range cfg.Syncer.Peers {
		ps.AddPeer(peer)
	}

	header := gateway.Header{
		GenesisID:  genesisBlock.ID(),
		UniqueID:   gateway.GenerateUniqueID(),
		NetAddress: syncerAddr,
	}
	s := syncer.New(syncerListener, cm, ps, header, syncer.WithLogger(log.Named("syncer")), syncer.WithMaxInboundPeers(256))
	defer s.Close()
	go s.Run()

	e, err := explorer.NewExplorer(cm, store, cfg.Index.BatchSize, cfg.Scanner, log.Named("explorer"))
	if err != nil {
		return fmt.Errorf("failed to create explorer: %w", err)
	}
	timeoutCtx, timeoutCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer timeoutCancel()
	defer e.Shutdown(timeoutCtx)

	var sources []exchangerates.Source
	sources = append(sources, exchangerates.NewKraken(map[string]string{
		exchangerates.CurrencyUSD: exchangerates.KrakenPairSiacoinUSD,
		exchangerates.CurrencyEUR: exchangerates.KrakenPairSiacoinEUR,
		exchangerates.CurrencyBTC: exchangerates.KrakenPairSiacoinBTC,
	}, cfg.ExchangeRates.Refresh))

	coinGeckoPro, coinGeckoAPIKey := false, os.Getenv("COINGECKO_DEMO_API_KEY")
	if coinGeckoAPIKey == "" {
		coinGeckoPro, coinGeckoAPIKey = true, os.Getenv("COINGECKO_PRO_API_KEY")
	}
	if coinGeckoAPIKey != "" {
		sources = append(sources, exchangerates.NewCoinGecko(coinGeckoPro, coinGeckoAPIKey, map[string]string{
			exchangerates.CurrencyUSD: exchangerates.CoinGeckoCurrencyUSD,
			exchangerates.CurrencyEUR: exchangerates.CoinGeckoCurrencyEUR,
			exchangerates.CurrencyCAD: exchangerates.CoinGeckoCurrencyCAD,
			exchangerates.CurrencyAUD: exchangerates.CoinGeckoCurrencyAUD,
			exchangerates.CurrencyGBP: exchangerates.CoinGeckoCurrencyGBP,
			exchangerates.CurrencyJPY: exchangerates.CoinGeckoCurrencyJPY,
			exchangerates.CurrencyCNY: exchangerates.CoinGeckoCurrencyCNY,
			exchangerates.CurrencyETH: exchangerates.CoinGeckoCurrencyETH,
			exchangerates.CurrencyBTC: exchangerates.CoinGeckoCurrencyBTC,
		}, exchangerates.CoinGeckoTokenSiacoin, cfg.ExchangeRates.Refresh))
	}

	ex, err := exchangerates.NewAverager(true, sources...)
	if err != nil {
		return fmt.Errorf("failed to create exchange rate source: %w", err)
	}
	go ex.Start(ctx)

	api := api.NewServer(e, cm, s, ex)
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/api") {
				r.URL.Path = strings.TrimPrefix(r.URL.Path, "/api")
				api.ServeHTTP(w, r)
				return
			}
			http.NotFound(w, r)
		}),
		ReadTimeout: 15 * time.Second,
	}
	defer server.Close()

	go func() {
		if err := server.Serve(httpListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal("http server failed", zap.Error(err))
		}
	}()

	log.Info("explored started", zap.String("network", cfg.Consensus.Network), zap.String("version", build.Version()), zap.String("http", cfg.HTTP.Address), zap.String("syncer", syncerAddr))

	<-ctx.Done()
	log.Info("shutting down")
	time.AfterFunc(3*time.Minute, func() {
		log.Fatal("failed to shut down within 3 minutes")
	})

	return nil
}

func main() {
	tryLoadConfig()

	flag.StringVar(&cfg.Directory, "dir", cfg.Directory, "directory to store node state in")
	flag.StringVar(&cfg.HTTP.Address, "http", cfg.HTTP.Address, "address to serve API on")
	flag.StringVar(&cfg.Consensus.Network, "network", cfg.Consensus.Network, "network to connect to")
	flag.StringVar(&cfg.Syncer.Address, "addr", cfg.Syncer.Address, "p2p address to listen on")
	flag.BoolVar(&cfg.Syncer.EnableUPNP, "upnp", cfg.Syncer.EnableUPNP, "attempt to forward ports and discover IP with UPnP")
	flag.Parse()

	if flag.Arg(0) == "version" {
		fmt.Println("explored", build.Version())
		fmt.Println("Commit:", build.Commit())
		fmt.Println("Build Date:", build.Time())
		return
	}

	checkFatalError("failed to open log file", os.MkdirAll(cfg.Directory, 0700))

	var logCores []zapcore.Core
	if cfg.Log.StdOut.Enabled {
		// if no log level is set for stdout, use the global log level
		if cfg.Log.StdOut.Level == "" {
			cfg.Log.StdOut.Level = cfg.Log.Level
		}

		var encoder zapcore.Encoder
		switch cfg.Log.StdOut.Format {
		case "json":
			encoder = jsonEncoder()
		default: // stdout defaults to human
			encoder = humanEncoder(cfg.Log.StdOut.EnableANSI)
		}

		// create the stdout logger
		level := parseLogLevel(cfg.Log.StdOut.Level)
		logCores = append(logCores, zapcore.NewCore(encoder, zapcore.Lock(os.Stdout), level))
	}

	if cfg.Log.File.Enabled {
		// if no log level is set for file, use the global log level
		if cfg.Log.File.Level == "" {
			cfg.Log.File.Level = cfg.Log.Level
		}

		// normalize log path
		if cfg.Log.File.Path == "" {
			cfg.Log.File.Path = filepath.Join(cfg.Directory, "explored.log")
		}

		// configure file logging
		var encoder zapcore.Encoder
		switch cfg.Log.File.Format {
		case "human":
			encoder = humanEncoder(false) // disable colors in file log
		default: // log file defaults to JSON
			encoder = jsonEncoder()
		}

		fileWriter, closeFn, err := zap.Open(cfg.Log.File.Path)
		checkFatalError("failed to open log file", err)
		defer closeFn()

		// create the file logger
		level := parseLogLevel(cfg.Log.File.Level)
		logCores = append(logCores, zapcore.NewCore(encoder, zapcore.Lock(fileWriter), level))
	}

	var log *zap.Logger
	if len(logCores) == 1 {
		log = zap.New(logCores[0], zap.AddCaller())
	} else {
		log = zap.New(zapcore.NewTee(logCores...), zap.AddCaller())
	}
	defer log.Sync()

	// redirect stdlib log to zap
	zap.RedirectStdLog(log.Named("stdlib"))

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	checkFatalError("daemon startup failed", runRootCmd(ctx, log))
}
