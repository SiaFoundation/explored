package exchangerates

import (
	"context"
	"testing"
	"time"
)

func TestKraken(t *testing.T) {
	const interval = time.Second

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	kraken := NewKraken(map[string]string{
		CurrencyUSD: KrakenPairSiacoinUSD,
		CurrencyEUR: KrakenPairSiacoinEUR,
	}, interval)
	go kraken.Start(ctx)

	time.Sleep(2 * interval)
	if price, err := kraken.Last("USD"); err != nil {
		t.Fatal(err)
	} else if price <= 0.0 {
		t.Fatalf("invalid price: %f", price)
	}

	if price, err := kraken.Last("EUR"); err != nil {
		t.Fatal(err)
	} else if price <= 0.0 {
		t.Fatalf("invalid price: %f", price)
	}

	if _, err := kraken.Last("UNK"); err == nil {
		t.Fatal("should fail for unmapped currency")
	}
}
