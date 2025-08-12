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
	// KrakenPairSiacoinBTC is the ID of SC/BTC pair in Kraken
	KrakenPairSiacoinBTC = "SCXBT"
)

type krakenAPI struct {
	client http.Client
}

type krakenPriceResponse struct {
	Error  []any `json:"error"`
	Result map[string]struct {
		B []string `json:"b"`
	} `json:"result"`
}

func newKrakenAPI() *krakenAPI {
	return &krakenAPI{}
}

func (k *krakenAPI) tickers(ctx context.Context, pairs []string) (map[string]float64, error) {
	pairParam := strings.Join(pairs, ",")
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.kraken.com/0/public/Ticker?pair="+url.PathEscape(pairParam), nil)
	if err != nil {
		return nil, err
	}

	response, err := k.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	var parsed krakenPriceResponse
	if err := json.NewDecoder(response.Body).Decode(&parsed); err != nil {
		return nil, err
	}

	rates := make(map[string]float64)
	for pair, data := range parsed.Result {
		if len(data.B) == 0 {
			continue
		}
		price, err := strconv.ParseFloat(data.B[0], 64)
		if err != nil {
			return nil, err
		}
		rates[pair] = price
	}

	return rates, nil
}

type kraken struct {
	pairMap map[string]string // User-specified currency -> Kraken pair
	refresh time.Duration
	client  *krakenAPI

	mu    sync.RWMutex
	rates map[string]float64 // Kraken pair -> rate
	err   error
}

// NewKraken returns an Source that gets data from Kraken.
func NewKraken(pairMap map[string]string, refresh time.Duration) Source {
	return &kraken{
		pairMap: pairMap,
		refresh: refresh,
		client:  newKrakenAPI(),
		rates:   make(map[string]float64),
	}
}

// Start implements Source.
func (k *kraken) Start(ctx context.Context) {
	ticker := time.NewTicker(k.refresh)
	defer ticker.Stop()

	var krakenPairs []string
	for _, krakenPair := range k.pairMap {
		krakenPairs = append(krakenPairs, krakenPair)
	}

	k.mu.Lock()
	k.rates, k.err = k.client.tickers(ctx, krakenPairs)
	k.mu.Unlock()

	for {
		select {
		case <-ticker.C:
			rates, err := k.client.tickers(ctx, krakenPairs)
			k.mu.Lock()
			k.rates, k.err = rates, err
			k.mu.Unlock()
		case <-ctx.Done():
			k.mu.Lock()
			k.err = ctx.Err()
			k.mu.Unlock()
			return
		}
	}
}

// Last implements Source.
func (k *kraken) Last(currency string) (float64, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	krakenPair, exists := k.pairMap[currency]
	if !exists {
		return 0, fmt.Errorf("currency %s not mapped to a Kraken pair", currency)
	}

	rate, ok := k.rates[krakenPair]
	if !ok {
		return 0, fmt.Errorf("rate for pair %s not available", krakenPair)
	}
	return rate, k.err
}
