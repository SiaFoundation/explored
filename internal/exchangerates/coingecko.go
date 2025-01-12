package exchangerates

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	// CoinGeckoPair is the ID of Siacoin in CoinGecko
	CoinGeckoSicaoinPair = "siacoin"
)

type coinGeckoAPI struct {
	apiKey string

	client http.Client
}

func newcoinGeckoAPI(apiKey string) *coinGeckoAPI {
	return &coinGeckoAPI{apiKey: apiKey}
}

type coinGeckoPriceResponse map[string]struct {
	USD float64 `json:"usd"`
}

// See https://docs.coingecko.com/reference/simple-price
func (k *coinGeckoAPI) ticker(pair string) (float64, error) {
	pair = strings.ToLower(pair)

	request, err := http.NewRequest(http.MethodGet, "https://api.coingecko.com/api/v3/simple/price?vs_currencies=usd&ids="+url.PathEscape(pair), nil)
	if err != nil {
		return 0, err
	}
	request.Header.Set("accept", "application/json")
	request.Header.Set("x-cg-demo-api-key", k.apiKey)

	response, err := k.client.Do(request)
	if err != nil {
		return 0, err
	}
	var parsed coinGeckoPriceResponse
	if err := json.NewDecoder(response.Body).Decode(&parsed); err != nil {
		return 0, err
	}

	price, ok := parsed[pair]
	if !ok {
		return 0, fmt.Errorf("no asset %s", pair)
	}
	return price.USD, nil
}

type coinGecko struct {
	pair    string
	refresh time.Duration
	client  *coinGeckoAPI

	mu   sync.Mutex
	rate float64
	err  error
}

func NewCoinGecko(apiKey string, pair string, refresh time.Duration) ExchangeRateSource {
	return &coinGecko{
		pair:    pair,
		refresh: refresh,
		client:  newcoinGeckoAPI(apiKey),
	}
}

// Start implements ExchangeRateSource.
func (c *coinGecko) Start(ctx context.Context) {
	ticker := time.NewTicker(c.refresh)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.mu.Lock()
			c.rate, c.err = c.client.ticker(c.pair)
			c.mu.Unlock()
		case <-ctx.Done():
			c.mu.Lock()
			c.err = ctx.Err()
			c.mu.Unlock()
			return
		}
	}
}

// Last implements ExchangeRateSource
func (c *coinGecko) Last() (rate float64, err error) {
	c.mu.Lock()
	rate, err = c.rate, c.err
	c.mu.Unlock()
	return
}
