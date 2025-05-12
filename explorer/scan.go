package explorer

import (
	"context"
	"fmt"
	"math"
	"net"
	"sync"
	"time"

	crhpv2 "go.sia.tech/core/rhp/v2"
	crhpv3 "go.sia.tech/core/rhp/v3"
	"go.sia.tech/core/types"
	crhpv4 "go.sia.tech/coreutils/rhp/v4"
	"go.sia.tech/coreutils/rhp/v4/siamux"
	rhpv2 "go.sia.tech/explored/internal/rhp/v2"
	rhpv3 "go.sia.tech/explored/internal/rhp/v3"
	"go.uber.org/zap"
)

func isSynced(b Block) bool {
	return time.Since(b.Timestamp) <= 3*time.Hour
}

func (e *Explorer) waitForSync(ctx context.Context) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		cs, err := e.Tip()
		if err != nil {
			e.log.Debug("Couldn't get tip, waiting", zap.Error(err))
		} else {
			b, err := e.Block(cs.ID)
			if err != nil {
				return err
			} else if isSynced(b) {
				break
			}
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			continue
		}
	}

	return nil
}

func rhpv2Settings(ctx context.Context, publicKey types.PublicKey, netAddress string) (crhpv2.HostSettings, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", netAddress)
	if err != nil {
		return crhpv2.HostSettings{}, fmt.Errorf("failed to connect to host: %w", err)
	}
	defer conn.Close()

	// default timeout if context doesn't have one
	deadline := time.Now().Add(30 * time.Second)
	if dl, ok := ctx.Deadline(); ok && !dl.IsZero() {
		deadline = dl
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return crhpv2.HostSettings{}, fmt.Errorf("failed to set deadline: %w", err)
	}

	t, err := crhpv2.NewRenterTransport(conn, publicKey)
	if err != nil {
		return crhpv2.HostSettings{}, fmt.Errorf("failed to establish rhpv2 transport: %w", err)
	}
	defer t.Close()

	settings, err := rhpv2.RPCSettings(ctx, t)
	if err != nil {
		return crhpv2.HostSettings{}, fmt.Errorf("failed to call settings RPC: %w", err)
	}
	return settings, nil
}

func rhpv3PriceTable(ctx context.Context, publicKey types.PublicKey, netAddress string) (priceTable crhpv3.HostPriceTable, err error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", netAddress)
	if err != nil {
		return crhpv3.HostPriceTable{}, fmt.Errorf("failed to connect to siamux port: %w", err)
	}
	defer conn.Close()

	// default timeout if context doesn't have one
	deadline := time.Now().Add(30 * time.Second)
	if dl, ok := ctx.Deadline(); ok && !dl.IsZero() {
		deadline = dl
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return crhpv3.HostPriceTable{}, fmt.Errorf("failed to set deadline: %w", err)
	}

	v3Session, err := rhpv3.NewSession(ctx, conn, publicKey, nil, nil)
	if err != nil {
		return crhpv3.HostPriceTable{}, fmt.Errorf("failed to establish rhpv3 transport: %w", err)
	}
	defer v3Session.Close()

	table, err := v3Session.ScanPriceTable()
	if err != nil {
		return crhpv3.HostPriceTable{}, fmt.Errorf("failed to scan price table: %w", err)
	}
	return table, nil
}

func (e *Explorer) scanV1Host(ctx context.Context, host UnscannedHost) (HostScan, error) {
	settings, err := rhpv2Settings(ctx, host.PublicKey, host.NetAddress)
	if err != nil {
		return HostScan{}, fmt.Errorf("scanV1Host: failed to get host settings: %w", err)
	}

	hostIP, _, err := net.SplitHostPort(settings.NetAddress)
	if err != nil {
		return HostScan{}, fmt.Errorf("scanV1Host: failed to parse net address: %w", err)
	}

	table, err := rhpv3PriceTable(ctx, host.PublicKey, net.JoinHostPort(hostIP, settings.SiaMuxPort))
	if err != nil {
		return HostScan{}, fmt.Errorf("scanV1Host: failed to get price table: %w", err)
	}

	resolved, err := net.ResolveIPAddr("ip", hostIP)
	if err != nil {
		return HostScan{}, fmt.Errorf("scanV1Host: failed to resolve host address: %w", err)
	}

	location, err := e.locator.Locate(resolved)
	if err != nil {
		e.log.Debug("Failed to resolve IP geolocation, not setting country code", zap.String("addr", host.NetAddress))
	}

	return HostScan{
		PublicKey: host.PublicKey,
		Location:  location,
		Success:   true,
		Timestamp: types.CurrentTimestamp(),

		Settings:   settings,
		PriceTable: table,
	}, nil
}

func (e *Explorer) scanV2Host(ctx context.Context, host UnscannedHost) (HostScan, error) {
	addr, ok := host.V2SiamuxAddr()
	if !ok {
		return HostScan{}, fmt.Errorf("host has no v2 siamux address")
	}

	transport, err := siamux.Dial(ctx, addr, host.PublicKey)
	if err != nil {
		return HostScan{}, fmt.Errorf("failed to dial host: %w", err)
	}
	defer transport.Close()

	settings, err := crhpv4.RPCSettings(ctx, transport)
	if err != nil {
		return HostScan{}, fmt.Errorf("failed to get host settings: %w", err)
	}

	hostIP, _, err := net.SplitHostPort(addr)
	if err != nil {
		return HostScan{}, fmt.Errorf("scanHost: failed to parse net address: %w", err)
	}

	resolved, err := net.ResolveIPAddr("ip", hostIP)
	if err != nil {
		return HostScan{}, fmt.Errorf("scanHost: failed to resolve host address: %w", err)
	}

	location, err := e.locator.Locate(resolved)
	if err != nil {
		e.log.Debug("Failed to resolve IP geolocation, not setting country code", zap.String("addr", host.NetAddress))
	}

	return HostScan{
		PublicKey: host.PublicKey,
		Location:  location,
		Success:   true,
		Timestamp: types.CurrentTimestamp(),

		V2Settings: settings,
	}, nil
}

func (e *Explorer) scanLoop() {
	ctx, cancel, err := e.tg.AddContext(context.Background())
	if err != nil {
		return
	}
	defer cancel()

	e.log.Info("Waiting for syncing to complete before scanning hosts")
	// don't scan hosts till we're at least nearly done with syncing
	if err := e.waitForSync(ctx); err != nil {
		e.log.Info("Interrupted before scanning started:", zap.Error(err))
		return
	}
	e.log.Info("Syncing complete, will begin scanning hosts")

	var wg sync.WaitGroup
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		now := types.CurrentTimestamp()
		lastAnnouncementCutoff := now.Add(-e.scanCfg.MinLastAnnouncement)

		batch, err := e.s.HostsForScanning(lastAnnouncementCutoff, e.scanCfg.NumThreads)
		if err != nil {
			e.log.Info("failed to get hosts for scanning:", zap.Error(err))
			return
		} else if len(batch) == 0 {
			select {
			case <-ctx.Done():
				e.log.Debug("shutdown:", zap.Error(ctx.Err()))
				return
			// wait until we call HostsForScanning again
			case <-time.After(e.scanCfg.ScanFrequency):
				continue // check again
			}
		}

		results := make([]HostScan, len(batch))
		for i, host := range batch {
			wg.Add(1)
			go func(i int, host UnscannedHost) {
				defer wg.Done()

				ctx, cancel := context.WithTimeout(ctx, e.scanCfg.ScanTimeout)
				defer cancel()

				var err error
				if host.IsV2() {
					results[i], err = e.scanV2Host(ctx, host)
				} else {
					results[i], err = e.scanV1Host(ctx, host)
				}
				now := types.CurrentTimestamp()
				if err != nil {
					e.log.Debug("host scan failed", zap.Stringer("pk", host.PublicKey), zap.Error(err))
					results[i] = HostScan{
						PublicKey: host.PublicKey,
						Success:   false,
						Error: func() *string {
							str := err.Error()
							return &str
						}(),
						Timestamp: now,
						NextScan:  now.Add(e.scanCfg.ScanInterval * time.Duration(math.Pow(2, float64(host.FailedInteractionsStreak)+1))),
					}
					return
				} else {
					e.mu.Lock()
					e.lastSuccessScan = time.Now()
					e.mu.Unlock()
					results[i].NextScan = now.Add(e.scanCfg.ScanInterval)
				}
			}(i, host)
		}
		wg.Wait()

		if err := e.s.AddHostScans(results...); err != nil {
			e.log.Info("failed to add host scans to DB:", zap.Error(err))
			return
		}
	}
}
