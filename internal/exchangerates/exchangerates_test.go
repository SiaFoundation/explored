package exchangerates

import (
	"context"
	"testing"
	"time"
)

type constantPriceSource struct {
	x float64
}

func (c *constantPriceSource) Start(ctx context.Context) {}

func (c *constantPriceSource) Last() (float64, error) {
	return c.x, nil
}

func newConstantPriceSource(x float64) *constantPriceSource {
	return &constantPriceSource{x: x}
}

func TestAverager(t *testing.T) {
	const interval = time.Second

	const (
		p1 = 1.0
		p2 = 10.0
		p3 = 100.0
	)
	s1 := newConstantPriceSource(p1)
	s2 := newConstantPriceSource(p2)
	s3 := newConstantPriceSource(p3)

	{
		ctx, cancel := context.WithCancel(context.Background())
		averager := NewAverager()
		go averager.Start(ctx)

		time.Sleep(2 * interval)
		_, err := averager.Last()
		// should get error: "no sources working"
		if err == nil {
			t.Fatal("should have gotten error for averager with no sources")
		}
		cancel()
	}

	{
		ctx, cancel := context.WithCancel(context.Background())
		averager := NewAverager(s1)
		go averager.Start(ctx)

		time.Sleep(2 * interval)

		price, err := averager.Last()
		if err != nil {
			t.Fatal(err)
		}

		const expect = p1
		if price != expect {
			t.Fatalf("wrong price, got %v, expected %v", price, expect)
		}
		cancel()
	}

	{
		ctx, cancel := context.WithCancel(context.Background())
		averager := NewAverager(s1, s2, s3)
		go averager.Start(ctx)

		time.Sleep(2 * interval)

		price, err := averager.Last()
		if err != nil {
			t.Fatal(err)
		}

		const expect = ((p1 + p2 + p3) / 3)
		if price != expect {
			t.Fatalf("wrong price, got %v, expected %v", price, expect)
		}
		cancel()
	}
}
