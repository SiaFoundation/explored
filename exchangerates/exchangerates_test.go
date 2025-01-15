package exchangerates

import (
	"context"
	"errors"
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

type errorPriceSource struct{}

func (c *errorPriceSource) Start(ctx context.Context) {}

func (c *errorPriceSource) Last() (float64, error) {
	return -1, errors.New("error")
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
	errorSource := &errorPriceSource{}

	{
		_, err := NewAverager(true)
		if err == nil {
			t.Fatal("should have gotten error for averager with no sources")
		}
	}

	{
		ctx, cancel := context.WithCancel(context.Background())
		averager, err := NewAverager(true, errorSource, errorSource, errorSource)
		if err != nil {
			t.Fatal(err)
		}
		go averager.Start(ctx)

		time.Sleep(2 * interval)
		_, err = averager.Last()
		// should get error: "no sources working"
		if err == nil {
			t.Fatal("should have gotten error for averager with no sources")
		}
		cancel()
	}

	{
		ctx, cancel := context.WithCancel(context.Background())
		averager, err := NewAverager(false, s1, s2, s3)
		if err != nil {
			t.Fatal(err)
		}
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

	{
		ctx, cancel := context.WithCancel(context.Background())
		averager, err := NewAverager(false, s1, s2, s3, errorSource)
		if err != nil {
			t.Fatal(err)
		}
		go averager.Start(ctx)

		time.Sleep(2 * interval)

		_, err = averager.Last()
		// Should get an error because the errorSource will fail
		// (ignoreOnError = false)
		if err == nil {
			t.Fatal("should have gotten error for averager with error source")
		}
		cancel()
	}

	{
		ctx, cancel := context.WithCancel(context.Background())
		averager, err := NewAverager(true, s1, s2, s3, errorSource)
		if err != nil {
			t.Fatal(err)
		}
		go averager.Start(ctx)

		time.Sleep(2 * interval)

		// Should not get an error because the errorSource will just be ignored
		// if at least one other source works (ignoreOnError = true)
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
