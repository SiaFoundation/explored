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

	kraken := NewKraken(KrakenSiacoinPair, interval)
	go kraken.Start(ctx)

	time.Sleep(2 * interval)
	price, err := kraken.Last()
	if err != nil {
		t.Fatal(err)
	}
	if price <= 0.0 {
		t.Fatalf("invalid price: %f", price)
	}
}
