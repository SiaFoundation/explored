// Package build contains build-time information.
package build

//go:generate go run gen.go

import "time"

// Commit returns the commit hash of explored
func Commit() string {
	return commit
}

// Version returns the version of explored
func Version() string {
	return version
}

// Time returns the time at which the binary was built.
func Time() time.Time {
	return time.Unix(buildTime, 0)
}
