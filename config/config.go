package config

import "time"

type (
	// HTTP contains the configuration for the HTTP server.
	HTTP struct {
		Address string `yaml:"address,omitempty"`
	}

	// Syncer contains the configuration for the syncer.
	Syncer struct {
		Address    string   `yaml:"address,omitempty"`
		Bootstrap  bool     `yaml:"bootstrap,omitempty"`
		EnableUPNP bool     `yaml:"enableUPnP,omitempty"`
		Peers      []string `yaml:"peers,omitempty"`
	}

	// Scanner contains the configuration for the host scanner.
	Scanner struct {
		// BatchSize represents the maximum number of hosts we will
		// simultaneously scan.
		BatchSize uint64 `yaml:"batchSize,omitempty"`
		// Timeout represents the maximum amount of time we will spend scanning
		// a single host.
		Timeout time.Duration `yaml:"timeout,omitempty"`
		// CheckAgainDelay represents the amount of time we will wait before
		// calling HostsForScanning again if the previous call returned zero
		// hosts to scan.
		CheckAgainDelay time.Duration `yaml:"checkAgainDelay,omitempty"`
		// MaxLastScan represents how frequently hosts will be scanned.  If a
		// scan is successful, the hosts next scan time will be set to
		// the current time plus MaxLastScan.  If it fails, the next scan time
		// is set to the current time plus MaxLastScan * pow(2, # of
		// consecutive failed scans).
		MaxLastScan time.Duration `yaml:"maxLastScan,omitempty"`
		// MinLastAnnouncement represents how far back we will search for
		// announcements to find hosts to scan.
		MinLastAnnouncement time.Duration `yaml:"minLastAnnouncement,omitempty"`
	}

	// Consensus contains the configuration for the consensus set.
	Consensus struct {
		Network string `yaml:"network,omitempty"`
	}

	// Index contains the configuration for the blockchain indexer
	Index struct {
		BatchSize int `yaml:"batchSize,omitempty"`
	}

	// ExchangeRates contains the configuration for the exchange rate clients.
	ExchangeRates struct {
		// refresh exchange rates this often
		Refresh time.Duration
	}

	// LogFile configures the file output of the logger.
	LogFile struct {
		Enabled bool   `yaml:"enabled,omitempty"`
		Level   string `yaml:"level,omitempty"` // override the file log level
		Format  string `yaml:"format,omitempty"`
		// Path is the path of the log file.
		Path string `yaml:"path,omitempty"`
	}

	// StdOut configures the standard output of the logger.
	StdOut struct {
		Level      string `yaml:"level,omitempty"` // override the stdout log level
		Enabled    bool   `yaml:"enabled,omitempty"`
		Format     string `yaml:"format,omitempty"`
		EnableANSI bool   `yaml:"enableANSI,omitempty"` //nolint:tagliatelle
	}

	// Log contains the configuration for the logger.
	Log struct {
		Level  string  `yaml:"level,omitempty"` // global log level
		StdOut StdOut  `yaml:"stdout,omitempty"`
		File   LogFile `yaml:"file,omitempty"`
	}

	// Config contains the configuration for the host.
	Config struct {
		Directory     string `yaml:"directory,omitempty"`
		AutoOpenWebUI bool   `yaml:"autoOpenWebUI,omitempty"`

		HTTP          HTTP          `yaml:"http,omitempty"`
		Consensus     Consensus     `yaml:"consensus,omitempty"`
		Syncer        Syncer        `yaml:"syncer,omitempty"`
		Scanner       Scanner       `yaml:"scanner,omitempty"`
		ExchangeRates ExchangeRates `yaml:"exchangeRates,omitempty"`
		Log           Log           `yaml:"log,omitempty"`
		Index         Index         `yaml:"index,omitempty"`
	}
)
