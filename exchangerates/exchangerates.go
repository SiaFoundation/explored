package exchangerates

import (
	"context"
	"errors"
)

// An ExchangeRateSource returns the price of 1 unit of an asset in USD.
type ExchangeRateSource interface {
	Last() (float64, error)
	Start(ctx context.Context)
}

type averager struct {
	ignoreOnError bool
	sources       []ExchangeRateSource
}

// NewAverager returns an exchange rate source that averages multiple exchange
// rates.
func NewAverager(ignoreOnError bool, sources ...ExchangeRateSource) (ExchangeRateSource, error) {
	if len(sources) == 0 {
		return nil, errors.New("no sources provided")
	}
	return &averager{
		ignoreOnError: ignoreOnError,
		sources:       sources,
	}, nil
}

// Start implements ExchangeRateSource.
func (a *averager) Start(ctx context.Context) {
	for i := range a.sources {
		go a.sources[i].Start(ctx)
	}
}

// Last implements ExchangeRateSource.
func (a *averager) Last() (float64, error) {
	sum, count := 0.0, 0.0
	for i := range a.sources {
		if v, err := a.sources[i].Last(); err == nil {
			sum += v
			count++
		} else if !a.ignoreOnError {
			return 0, err
		}
	}

	if count == 0 {
		return 0, errors.New("no sources working")
	}
	return sum / count, nil
}
