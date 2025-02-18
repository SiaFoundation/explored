package geoip

import (
	_ "embed" // needed for geolocation database
	"errors"
	"net"
	"sync"

	"github.com/oschwald/geoip2-golang"
)

//go:embed GeoLite2-City.mmdb
var maxMindCityDB []byte

// A Location represents an ISO 3166-1 A-2 country codes and an approximate
// latitude/longitude.
type Location struct {
	CountryCode string `json:"countryCode"`

	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
}

// A Locator maps IP addresses to their location.
// It is assumed that it implementations are thread-safe.
type Locator interface {
	// Close closes the Locator.
	Close() error
	// Locate maps IP addresses to a Location.
	Locate(ip *net.IPAddr) (Location, error)
}

type maxMindLocator struct {
	mu sync.Mutex

	db *geoip2.Reader
}

// Locate implements Locator.
func (m *maxMindLocator) Locate(addr *net.IPAddr) (Location, error) {
	if addr == nil {
		return Location{}, errors.New("nil IP")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	record, err := m.db.City(addr.IP)
	if err != nil {
		return Location{}, err
	}
	return Location{
		CountryCode: record.Country.IsoCode,
		Latitude:    record.Location.Latitude,
		Longitude:   record.Location.Longitude,
	}, nil
}

// Close implements Locator.
func (m *maxMindLocator) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.db.Close()
}

// NewMaxMindLocator returns a Locator that uses an underlying MaxMind
// database.  If no path is provided, a default embedded GeoLite2-City database
// is used.
func NewMaxMindLocator(path string) (Locator, error) {
	var db *geoip2.Reader
	var err error
	if path == "" {
		db, err = geoip2.FromBytes(maxMindCityDB)
	} else {
		db, err = geoip2.Open(path)
	}
	if err != nil {
		return nil, err
	}

	return &maxMindLocator{db: db}, nil
}
