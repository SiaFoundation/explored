package explorer

import (
	"math"
	"testing"
	"time"
)

func TestScanBackoff(t *testing.T) {
	tests := []struct {
		name       string
		interval   time.Duration
		maxBackoff time.Duration
		streak     uint64
		want       time.Duration
	}{
		{
			name:       "exponential backoff",
			interval:   time.Minute,
			maxBackoff: time.Hour,
			streak:     1,
			want:       4 * time.Minute,
		},
		{
			name:       "capped at max backoff",
			interval:   time.Minute,
			maxBackoff: 10 * time.Minute,
			streak:     4,
			want:       10 * time.Minute,
		},
		{
			name:       "huge streak caps instead of overflowing",
			interval:   time.Minute,
			maxBackoff: time.Hour,
			streak:     math.MaxUint64,
			want:       time.Hour,
		},
		{
			name:       "interval larger than max backoff floors the cap",
			interval:   7 * 24 * time.Hour,
			maxBackoff: 3 * 24 * time.Hour,
			streak:     5,
			want:       7 * 24 * time.Hour,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := scanBackoff(tt.interval, tt.maxBackoff, tt.streak); got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}
