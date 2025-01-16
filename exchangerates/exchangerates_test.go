package exchangerates

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type constantExchangeRateSource struct {
	x float64

	mu   sync.Mutex
	rate float64
}

func (c *constantExchangeRateSource) Start(ctx context.Context) {
	c.mu.Lock()
	c.rate = c.x
	c.mu.Unlock()
}

func (c *constantExchangeRateSource) Last(string) (rate float64, err error) {
	c.mu.Lock()
	rate, err = c.rate, nil
	c.mu.Unlock()
	return
}

func newConstantExchangeRateSource(x float64) *constantExchangeRateSource {
	return &constantExchangeRateSource{x: x}
}

type errorExchangeRateSource struct{}

func (c *errorExchangeRateSource) Start(ctx context.Context) {}

func (c *errorExchangeRateSource) Last(string) (float64, error) {
	return -1, errors.New("error")
}

func TestAveragerLastBeforeStart(t *testing.T) {
	averager, err := NewAverager(false, newConstantExchangeRateSource(1.0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := averager.Last(CurrencyUSD); err == nil {
		t.Fatal("should be error if we call Last before Start")
	}
}

func TestAverager(t *testing.T) {
	const interval = time.Second

	const (
		p1 = 1.0
		p2 = 10.0
		p3 = 100.0
	)
	s1 := newConstantExchangeRateSource(p1)
	s2 := newConstantExchangeRateSource(p2)
	s3 := newConstantExchangeRateSource(p3)
	errorSource := &errorExchangeRateSource{}

	tests := []struct {
		name          string
		ignoreOnError bool
		sources       []ExchangeRateSource
		expectedPrice float64
		expectError   bool
		errorMessage  string
	}{
		{
			name:          "No sources provided",
			ignoreOnError: true,
			sources:       nil,
			expectError:   true,
			errorMessage:  "Should have gotten error for averager with no sources",
		},
		{
			name:          "All sources fail",
			ignoreOnError: true,
			sources:       []ExchangeRateSource{errorSource, errorSource, errorSource},
			expectError:   true,
			errorMessage:  "Should have gotten error for averager with no working sources",
		},
		{
			name:          "Valid sources without errors",
			ignoreOnError: false,
			sources:       []ExchangeRateSource{s1, s2, s3},
			expectedPrice: (p1 + p2 + p3) / 3,
			expectError:   false,
		},
		{
			name:          "One error source without ignoreOnError",
			ignoreOnError: false,
			sources:       []ExchangeRateSource{s1, s2, s3, errorSource},
			expectError:   true,
			errorMessage:  "Should have gotten error for averager with error source and ignoreOnError disabled",
		},
		{
			name:          "One error source with ignoreOnError",
			ignoreOnError: true,
			sources:       []ExchangeRateSource{s1, s2, s3, errorSource},
			expectedPrice: (p1 + p2 + p3) / 3,
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			averager, err := NewAverager(tt.ignoreOnError, tt.sources...)
			if err != nil {
				if !tt.expectError {
					t.Fatal(err)
				}
				return
			}
			go averager.Start(ctx)

			time.Sleep(2 * interval)

			price, err := averager.Last(CurrencyUSD)
			if tt.expectError {
				if err == nil {
					t.Fatal(tt.errorMessage)
				}
				return
			}

			if err != nil {
				t.Fatal(err)
			}

			if price != tt.expectedPrice {
				t.Fatalf("wrong price, got %v, expected %v", price, tt.expectedPrice)
			}
		})
	}
}
