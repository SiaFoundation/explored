package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime/debug"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/term"
)

var commit = "?"
var timestamp = "?"

func init() {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	modified := false
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			commit = setting.Value[:8]
		case "vcs.time":
			timestamp = setting.Value
		case "vcs.modified":
			modified = setting.Value == "true"
		}
	}
	if modified {
		commit += " (modified)"
	}
}

func check(context string, err error, logger *zap.Logger) {
	if err != nil {
		log.Fatalf("%v: %v", context, err)
	}
}

func getAPIPassword(logger *zap.Logger) string {
	apiPassword := os.Getenv("EXPLORED_API_PASSWORD")
	if apiPassword != "" {
		logger.Info("env: Using EXPLORED_API_PASSWORD environment variable")
	} else {
		fmt.Print("Enter API password: ")
		pw, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		check("Could not read API password:", err, logger)
		if err != nil {
			log.Fatal(err)
		}
		apiPassword = string(pw)
	}
	return apiPassword
}

func main() {
	// configure console logging note: this is configured before anything else
	// to have consistent logging. File logging will be added after the cli
	// flags and config is parsed
	consoleCfg := zap.NewProductionEncoderConfig()
	consoleCfg.TimeKey = "" // prevent duplicate timestamps
	consoleCfg.EncodeTime = zapcore.RFC3339TimeEncoder
	consoleCfg.EncodeDuration = zapcore.StringDurationEncoder
	consoleCfg.EncodeLevel = zapcore.CapitalColorLevelEncoder
	consoleCfg.StacktraceKey = ""
	consoleCfg.CallerKey = ""
	consoleEncoder := zapcore.NewConsoleEncoder(consoleCfg)

	// only log info messages to console unless stdout logging is enabled
	consoleCore := zapcore.NewCore(consoleEncoder, zapcore.Lock(os.Stdout), zap.NewAtomicLevelAt(zap.DebugLevel))
	log := zap.New(consoleCore, zap.AddCaller())
	defer log.Sync()
	// redirect stdlib log to zap
	zap.RedirectStdLog(log.Named("stdlib"))

	gatewayAddr := flag.String("addr", ":9981", "p2p address to listen on")
	apiAddr := flag.String("http", "localhost:9980", "address to serve API on")
	dir := flag.String("dir", ".", "directory to store node state in")
	network := flag.String("network", "mainnet", "network to connect to")
	upnp := flag.Bool("upnp", true, "attempt to forward ports and discover IP with UPnP")
	flag.Parse()

	log.Info("explored v0.0.0")
	if flag.Arg(0) == "version" {
		log.Info("Commit Hash:", zap.String("hash", commit))
		log.Info("Commit Date:", zap.String("date", timestamp))
		return
	}

	apiPassword := getAPIPassword(log)
	l, err := net.Listen("tcp", *apiAddr)
	if err != nil {
		log.Fatal("Failed to create listener", zap.Error(err))
	}

	n, err := newNode(*gatewayAddr, *dir, *network, *upnp, log)
	if err != nil {
		log.Fatal("Failed to create node", zap.Error(err))
	}
	log.Info("p2p: Listening on", zap.String("addr", n.s.Addr()))
	stop := n.Start()
	log.Info("api: Listening on", zap.String("addr", l.Addr().String()))
	go startWeb(l, n, apiPassword)

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt)
	<-signalCh
	log.Info("Shutting down...")
	stop()
}
