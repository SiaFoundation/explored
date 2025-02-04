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
	// CoinGeckoCurrencyCAD is the name of Canadian dollars in CoinGecko.
	CoinGeckoCurrencyCAD = "cad"
	// CoinGeckoCurrencyAUD is the name of Australian dollars in CoinGecko.
	CoinGeckoCurrencyAUD = "aud"
	// CoinGeckoCurrencyGBP is the name of British pounds in CoinGecko.
	CoinGeckoCurrencyGBP = "gbp"
	// CoinGeckoCurrencyJPY is the name of Japanese yen in CoinGecko.
	CoinGeckoCurrencyJPY = "jpy"
	// CoinGeckoCurrencyCNY is the name of Chinese yuan in CoinGecko.
	CoinGeckoCurrencyCNY = "cny"
	// CoinGeckoCurrencyBTC is the name of Bitcoin in CoinGecko.
	CoinGeckoCurrencyBTC = "btc"
	// CoinGeckoCurrencyETH is the name of Ethereum in CoinGecko.
	CoinGeckoCurrencyETH = "eth"
)

const (
	demoBaseURL = "https://api.coingecko.com"
	proBaseURL  = "https://pro-api.coingecko.com"
)

type coinGeckoAPI struct {
	pro    bool
	apiKey string
	client http.Client
}

func newCoinGeckoAPI(pro bool, apiKey string) *coinGeckoAPI {
	return &coinGeckoAPI{pro: pro, apiKey: apiKey}
}

type coinGeckoPriceResponse map[string]map[string]float64

func (c *coinGeckoAPI) baseURL() string {
	if c.pro {
		return proBaseURL
	}
	return demoBaseURL
}

// See https://docs.coingecko.com/reference/simple-price
func (c *coinGeckoAPI) tickers(ctx context.Context, currencies []string, token string) (map[string]float64, error) {
	vsCurrencies := strings.ToLower(strings.Join(currencies, ","))
	token = strings.ToLower(token)

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf(
		"%s/api/v3/simple/price?vs_currencies=%s&ids=%s",
		c.baseURL(), vsCurrencies, token), nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("accept", "application/json")
	if c.pro {
		request.Header.Set("x-cg-pro-api-key", c.apiKey)
	} else {
		request.Header.Set("x-cg-demo-api-key", c.apiKey)
	}

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

// NewCoinGecko creates an Source with user-specified mappings
func NewCoinGecko(pro bool, apiKey string, pairMap map[string]string, token string, refresh time.Duration) Source {
	return &coinGecko{
		token:   token,
		pairMap: pairMap,
		refresh: refresh,
		client:  newCoinGeckoAPI(pro, apiKey),
		rates:   make(map[string]float64),
	}
}

// Start implements Source.
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

// Last implements Source.
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
