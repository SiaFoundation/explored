package explorer

import (
	"context"
	"fmt"
	"math"
	"net"
	"time"

	crhpv2 "go.sia.tech/core/rhp/v2"
	crhpv3 "go.sia.tech/core/rhp/v3"
	"go.sia.tech/core/types"
	crhpv4 "go.sia.tech/coreutils/rhp/v4"
	"go.sia.tech/coreutils/rhp/v4/siamux"
	"go.sia.tech/explored/geoip"
	rhpv2 "go.sia.tech/explored/internal/rhp/v2"
	rhpv3 "go.sia.tech/explored/internal/rhp/v3"
	"go.uber.org/zap"
)

func isSynced(b Block) bool {
	return time.Since(b.Timestamp) <= 3*time.Hour
}

func (e *Explorer) waitForSync() error {
	ticker := time.NewTicker(1 * time.Second)
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
		case <-e.ctx.Done():
			return e.ctx.Err()
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

func (e *Explorer) scanV1Host(locator geoip.Locator, host UnscannedHost) (HostScan, error) {
	ctx, cancel := context.WithTimeout(e.ctx, e.scanCfg.ScanTimeout)
	defer cancel()

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

	location, err := locator.Locate(resolved)
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

func (e *Explorer) scanV2Host(locator geoip.Locator, host UnscannedHost) (HostScan, error) {
	ctx, cancel := context.WithTimeout(e.ctx, e.scanCfg.ScanTimeout)
	defer cancel()

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

	location, err := locator.Locate(resolved)
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

func (e *Explorer) isClosed() bool {
	select {
	case <-e.ctx.Done():
		return true
	default:
		return false
	}
}

func (e *Explorer) scanHosts() {
	e.log.Info("Waiting for syncing to complete before scanning hosts")
	// don't scan hosts till we're at least nearly done with syncing
	if err := e.waitForSync(); err != nil {
		e.log.Info("Interrupted before scanning started:", zap.Error(err))
		return
	}
	e.log.Info("Syncing complete, will begin scanning hosts")

	locator, err := geoip.NewMaxMindLocator("")
	if err != nil {
		e.log.Info("failed to create geoip database:", zap.Error(err))
		return
	}
	defer locator.Close()

	for !e.isClosed() {
		now := types.CurrentTimestamp()
		lastAnnouncementCutoff := now.Add(-e.scanCfg.MinLastAnnouncement)

		batch, err := e.s.HostsForScanning(lastAnnouncementCutoff, e.scanCfg.NumThreads)
		if err != nil {
			e.log.Info("failed to get hosts for scanning:", zap.Error(err))
			return
		} else if len(batch) == 0 {
			select {
			case <-e.ctx.Done():
				e.log.Debug("shutdown:", zap.Error(e.ctx.Err()))
				return
			// wait until we call HostsForScanning again
			case <-time.After(e.scanCfg.ScanFrequency):
				continue // check again
			}
		}

		results := make([]HostScan, len(batch))
		for i, host := range batch {
			e.wg.Add(1)
			go func(i int, host UnscannedHost) {
				defer e.wg.Done()

				var err error
				if host.IsV2() {
					results[i], err = e.scanV2Host(locator, host)
				} else {
					results[i], err = e.scanV1Host(locator, host)
				}
				now := types.CurrentTimestamp()
				if err != nil {
					e.log.Debug("host scan failed", zap.Stringer("pk", host.PublicKey), zap.Error(err))
					results[i] = HostScan{
						PublicKey: host.PublicKey,
						Success:   false,
						Timestamp: now,
						NextScan:  now.Add(e.scanCfg.ScanInterval * time.Duration(math.Pow(2, float64(host.FailedInteractionsStreak)+1))),
					}
					return
				} else {
					results[i].NextScan = now.Add(e.scanCfg.ScanInterval)
				}
			}(i, host)
		}
		e.wg.Wait()

		if err := e.s.AddHostScans(results); err != nil {
			e.log.Info("failed to add host scans to DB:", zap.Error(err))
			return
		}
	}
}
