package exchangerates

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// KrakenPairSiacoinUSD is the ID of SC/USD pair in Kraken
	KrakenPairSiacoinUSD = "SCUSD"
	// KrakenPairSiacoinEUR is the ID of SC/EUR pair in Kraken
	KrakenPairSiacoinEUR = "SCEUR"
)

type krakenAPI struct {
	client http.Client
}

type krakenPriceResponse struct {
	Error  []any `json:"error"`
	Result map[string]struct {
		A []string `json:"a"`
		B []string `json:"b"`
		C []string `json:"c"`
		V []string `json:"v"`
		P []string `json:"p"`
		T []int    `json:"t"`
		L []string `json:"l"`
		H []string `json:"h"`
		O string   `json:"o"`
	} `json:"result"`
}

func newKrakenAPI() *krakenAPI {
	return &krakenAPI{}
}

// See https://docs.kraken.com/api/docs/rest-api/get-ticker-information
func (k *krakenAPI) ticker(ctx context.Context, pair string) (float64, error) {
	pair = strings.ToUpper(pair)

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.kraken.com/0/public/Ticker?pair="+url.PathEscape(pair), nil)
	if err != nil {
		return 0, err
	}
	response, err := k.client.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()

	var parsed krakenPriceResponse
	if err := json.NewDecoder(response.Body).Decode(&parsed); err != nil {
		return 0, err
	}

	p := parsed.Result[pair]
	if len(p.B) == 0 {
		return 0, fmt.Errorf("no asset %s", pair)
	}
	price, err := strconv.ParseFloat(p.B[0], 64)
	if err != nil {
		return 0, err
	}

	return price, nil
}

type kraken struct {
	pair    string
	refresh time.Duration
	client  *krakenAPI

	mu   sync.Mutex
	rate float64
	err  error
}

// NewKraken returns an ExchangeRateSource that gets data from Kraken.
func NewKraken(pair string, refresh time.Duration) ExchangeRateSource {
	return &kraken{
		pair:    pair,
		refresh: refresh,
		client:  newKrakenAPI(),
	}
}

// Start implements ExchangeRateSource.
func (k *kraken) Start(ctx context.Context) {
	ticker := time.NewTicker(k.refresh)
	defer ticker.Stop()

	k.mu.Lock()
	k.rate, k.err = k.client.ticker(ctx, k.pair)
	k.mu.Unlock()
	for {
		select {
		case <-ticker.C:
			k.mu.Lock()
			k.rate, k.err = k.client.ticker(ctx, k.pair)
			k.mu.Unlock()
		case <-ctx.Done():
			k.mu.Lock()
			k.err = ctx.Err()
			k.mu.Unlock()
			return
		}
	}
}

// Last implements ExchangeRateSource
func (k *kraken) Last() (rate float64, err error) {
	k.mu.Lock()
	rate, err = k.rate, k.err
	k.mu.Unlock()
	return
}
