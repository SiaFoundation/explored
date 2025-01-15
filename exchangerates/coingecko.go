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
	// CoinGeckoCurrencyBTC is the name of bitcoin in CoinGecko.
	CoinGeckoCurrencyBTC = "btc"
)

type coinGeckoAPI struct {
	apiKey string
	client http.Client
}

func newCoinGeckoAPI(apiKey string) *coinGeckoAPI {
	return &coinGeckoAPI{apiKey: apiKey}
}

type coinGeckoPriceResponse map[string]map[string]float64

// See https://docs.coingecko.com/reference/simple-price
func (c *coinGeckoAPI) tickers(ctx context.Context, currencies []string, token string) (map[string]float64, error) {
	vsCurrencies := strings.ToLower(strings.Join(currencies, ","))
	token = strings.ToLower(token)

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf(
		"https://api.coingecko.com/api/v3/simple/price?vs_currencies=%s&ids=%s",
		vsCurrencies, token), nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("accept", "application/json")
	request.Header.Set("x-cg-demo-api-key", c.apiKey)

	response, err := c.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	var parsed coinGeckoPriceResponse
	if err := json.NewDecoder(response.Body).Decode(&parsed); err != nil {
		return nil, err
	}

	asset, ok := parsed[token]
	if !ok {
		return nil, fmt.Errorf("no asset %s", token)
	}

	return asset, nil
}

type coinGecko struct {
	token   string
	pairMap map[string]string // User-specified currency -> CoinGecko currency
	refresh time.Duration
	client  *coinGeckoAPI

	mu    sync.Mutex
	rates map[string]float64 // CoinGecko currency -> rate
	err   error
}

// NewCoinGecko creates an ExchangeRateSource with user-specified mappings
func NewCoinGecko(apiKey string, pairMap map[string]string, token string, refresh time.Duration) ExchangeRateSource {
	return &coinGecko{
		token:   token,
		pairMap: pairMap,
		refresh: refresh,
		client:  newCoinGeckoAPI(apiKey),
		rates:   make(map[string]float64),
	}
}

// Start implements ExchangeRateSource.
func (c *coinGecko) Start(ctx context.Context) {
	ticker := time.NewTicker(c.refresh)
	defer ticker.Stop()

	var currencies []string
	for _, coinGeckoCurrency := range c.pairMap {
		currencies = append(currencies, coinGeckoCurrency)
	}

	c.mu.Lock()
	c.rates, c.err = c.client.tickers(ctx, currencies, c.token)
	c.mu.Unlock()

	for {
		select {
		case <-ticker.C:
			c.mu.Lock()
			c.rates, c.err = c.client.tickers(ctx, currencies, c.token)
			c.mu.Unlock()
		case <-ctx.Done():
			c.mu.Lock()
			c.err = ctx.Err()
			c.mu.Unlock()
			return
		}
	}
}

// Last implements ExchangeRateSource.
func (c *coinGecko) Last(currency string) (float64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	coinGeckoCurrency, exists := c.pairMap[currency]
	if !exists {
		return 0, fmt.Errorf("currency %s not mapped to a CoinGecko currency", currency)
	}

	rate, ok := c.rates[coinGeckoCurrency]
	if !ok {
		return 0, fmt.Errorf("rate for currency %s not available", currency)
	}
	return rate, c.err
}
