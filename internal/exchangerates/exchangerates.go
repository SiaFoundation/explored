package exchangerates

import (
	"context"
	"errors"
)

type ExchangeRateSource interface {
	Last() (float64, error)
	Start(ctx context.Context)
}

type averager struct {
	sources []ExchangeRateSource
}

func NewAverager(sources ...ExchangeRateSource) ExchangeRateSource {
	return &averager{
		sources: sources,
	}
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
		} else {
			return 0, err
		}
	}

	if count == 0 {
		return 0, errors.New("no sources working")
	}
	return sum / count, nil
}
