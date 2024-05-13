package sqlite

import (
	"fmt"

	"go.sia.tech/explored/explorer"
)

// Metrics implements explorer.Store
func (s *Store) Metrics() (explorer.Metrics, error) {
	tip, err := s.Tip()
	if err != nil {
		return explorer.Metrics{}, fmt.Errorf("failed to get tip: %w", err)
	}

	var m explorer.Metrics
	m.Height = tip.Height

	return m, nil
}
