package exchangerates

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	// CoinGeckoTokenSiacoin is the token ID of Siacoin in CoinGecko
	CoinGeckoTokenSiacoin = "siacoin"
)

const (
	// CoinGeckoCurrencyUSD is the name of US dollars in CoinGecko.
	CoinGeckoCurrencyUSD = "usd"
	// CoinGeckoCurrencyEUR is the name of euros in CoinGecko.
	CoinGeckoCurrencyEUR = "eur"
)

type coinGeckoAPI struct {
	apiKey string

	client http.Client
}

func newcoinGeckoAPI(apiKey string) *coinGeckoAPI {
	return &coinGeckoAPI{apiKey: apiKey}
}

type coinGeckoPriceResponse map[string]map[string]float64

// See https://docs.coingecko.com/reference/simple-price
func (k *coinGeckoAPI) ticker(ctx context.Context, currency, token string) (float64, error) {
	currency = strings.ToLower(currency)
	token = strings.ToLower(token)

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://api.coingecko.com/api/v3/simple/price?vs_currencies=%s&ids=%s", currency, token), nil)
	if err != nil {
		return 0, err
	}
	request.Header.Set("accept", "application/json")
	request.Header.Set("x-cg-demo-api-key", k.apiKey)

	response, err := k.client.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()

	var parsed coinGeckoPriceResponse
	if err := json.NewDecoder(response.Body).Decode(&parsed); err != nil {
		return 0, err
	}

	asset, ok := parsed[token]
	if !ok {
		return 0, fmt.Errorf("no asset %s", token)
	}
	price, ok := asset[currency]
	if !ok {
		return 0, fmt.Errorf("no currency %s", currency)
	}
	return price, nil
}

type coinGecko struct {
	currency string
	token    string
	refresh  time.Duration
	client   *coinGeckoAPI

	mu   sync.Mutex
	rate float64
	err  error
}

// NewCoinGecko returns an ExchangeRateSource that gets data from CoinGecko.
func NewCoinGecko(apiKey, currency, token string, refresh time.Duration) ExchangeRateSource {
	return &coinGecko{
		currency: currency,
		token:    token,
		refresh:  refresh,
		client:   newcoinGeckoAPI(apiKey),
	}
}

// Start implements ExchangeRateSource.
func (c *coinGecko) Start(ctx context.Context) {
	ticker := time.NewTicker(c.refresh)
	defer ticker.Stop()

	c.mu.Lock()
	c.rate, c.err = c.client.ticker(ctx, c.currency, c.token)
	c.mu.Unlock()
	for {
		select {
		case <-ticker.C:
			c.mu.Lock()
			c.rate, c.err = c.client.ticker(ctx, c.currency, c.token)
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
