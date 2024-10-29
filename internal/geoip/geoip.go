package geoip

import (
	_ "embed" // needed for geolocation database
	"errors"
	"net"
	"os"

	"github.com/ip2location/ip2location-go"
)

//go:embed IP2LOCATION-LITE-DB1.BIN
var ip2LocationDB []byte

// A Locator maps IP addresses to their location.
type Locator interface {
	// Close closes the Locator.
	Close() error
	// CountryCode maps IP addresses to ISO 3166-1 A-2 country codes.
	CountryCode(ip *net.IPAddr) (string, error)
}

type ip2Location struct {
	path string
	db   *ip2location.DB
}

// Close implements Locator.
func (ip *ip2Location) Close() error {
	ip.db.Close()
	return os.Remove(ip.path)
}

// CountryCode implements Locator.
func (ip *ip2Location) CountryCode(addr *net.IPAddr) (string, error) {
	if ip == nil {
		return "", errors.New("nil IP")
	}

	loc, err := ip.db.Get_country_short(addr.String())
	if err != nil {
		return "", err
	}
	return loc.Country_short, nil
}

// NewIP2LocationLocator returns a Locator that uses an underlying IP2Location
// database.  If no path is provided, a default embedded LITE database is used.
func NewIP2LocationLocator(path string) (Locator, error) {
	// Unfortunately, ip2location.OpenDB only accepts a file path.  So we need
	// to write the embedded file to a temporary file on disk, and use that
	// instead.
	if path == "" {
		f, err := os.CreateTemp("", "geoip")
		if err != nil {
			return nil, err
		} else if _, err := f.Write(ip2LocationDB); err != nil {
			return nil, err
		} else if err := f.Sync(); err != nil {
			return nil, err
		} else if err := f.Close(); err != nil {
			return nil, err
		}
		path = f.Name()
	}

	db, err := ip2location.OpenDB(path)
	if err != nil {
		return nil, err
	}
	return &ip2Location{path: path, db: db}, nil
}
