package explorer

import (
	"context"
	"fmt"
	"net"
	"time"

	crhpv2 "go.sia.tech/core/rhp/v2"
	"go.sia.tech/core/types"
	crhpv4 "go.sia.tech/coreutils/rhp/v4"
	"go.sia.tech/explored/internal/geoip"
	rhpv2 "go.sia.tech/explored/internal/rhp/v2"
	rhpv3 "go.sia.tech/explored/internal/rhp/v3"
	"go.uber.org/zap"
)

const (
	scanBatchSize = 100
)

func isSynced(b Block) bool {
	return time.Since(b.Timestamp) <= 3*time.Hour
}

func (e *Explorer) waitForSync() error {
	ticker := time.NewTicker(10 * time.Second)
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

func (e *Explorer) scanV1Host(locator geoip.Locator, host Host) (HostScan, error) {
	ctx, cancel := context.WithTimeout(e.ctx, e.scanCfg.Timeout)
	defer cancel()

	dialer := (&net.Dialer{})

	conn, err := dialer.DialContext(ctx, "tcp", host.NetAddress)
	if err != nil {
		return HostScan{}, fmt.Errorf("scanHost: failed to connect to host: %w", err)
	}
	defer conn.Close()

	transport, err := crhpv2.NewRenterTransport(conn, host.PublicKey)
	if err != nil {
		return HostScan{}, fmt.Errorf("scanHost: failed to establish v2 transport: %w", err)
	}
	defer transport.Close()

	settings, err := rhpv2.RPCSettings(ctx, transport)
	if err != nil {
		return HostScan{}, fmt.Errorf("scanHost: failed to get host settings: %w", err)
	}

	hostIP, _, err := net.SplitHostPort(settings.NetAddress)
	if err != nil {
		return HostScan{}, fmt.Errorf("scanHost: failed to parse net address: %w", err)
	}

	resolved, err := net.ResolveIPAddr("ip", hostIP)
	if err != nil {
		return HostScan{}, fmt.Errorf("scanHost: failed to resolve host address: %w", err)
	}

	countryCode, err := locator.CountryCode(resolved)
	if err != nil {
		e.log.Debug("Failed to resolve IP geolocation, not setting country code", zap.String("addr", host.NetAddress))
		countryCode = ""
	}

	v3Addr := net.JoinHostPort(hostIP, settings.SiaMuxPort)
	v3Session, err := rhpv3.NewSession(ctx, host.PublicKey, v3Addr, e.cm, nil)
	if err != nil {
		return HostScan{}, fmt.Errorf("scanHost: failed to establish v3 transport: %w", err)
	}

	table, err := v3Session.ScanPriceTable()
	if err != nil {
		return HostScan{}, fmt.Errorf("scanHost: failed to scan price table: %w", err)
	}

	return HostScan{
		PublicKey:   host.PublicKey,
		CountryCode: countryCode,
		Success:     true,
		Timestamp:   types.CurrentTimestamp(),

		Settings:   settings,
		PriceTable: table,
	}, nil
}

func (e *Explorer) scanV2Host(locator geoip.Locator, host Host) (HostScan, error) {
	ctx, cancel := context.WithTimeout(e.ctx, e.scanCfg.Timeout)
	defer cancel()

	addr, ok := host.V2SiamuxAddr()
	if !ok {
		return HostScan{}, fmt.Errorf("host has no v2 siamux address")
	}

	transport, err := crhpv4.DialSiaMux(ctx, addr, host.PublicKey)
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

	countryCode, err := locator.CountryCode(resolved)
	if err != nil {
		e.log.Debug("Failed to resolve IP geolocation, not setting country code", zap.String("addr", host.NetAddress))
		countryCode = ""
	}

	return HostScan{
		PublicKey:   host.PublicKey,
		CountryCode: countryCode,
		Success:     true,
		Timestamp:   types.CurrentTimestamp(),

		RHPV4Settings: settings,
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

	locator, err := geoip.NewIP2LocationLocator("")
	if err != nil {
		e.log.Info("failed to create geoip database:", zap.Error(err))
		return
	}
	defer locator.Close()

	for !e.isClosed() {
		now := types.CurrentTimestamp()
		lastAnnouncementCutoff := now.Add(-e.scanCfg.MinLastAnnouncement)

		batch, err := e.s.HostsForScanning(lastAnnouncementCutoff, scanBatchSize)
		if err != nil {
			e.log.Info("failed to get hosts for scanning:", zap.Error(err))
			return
		} else if len(batch) == 0 {
			select {
			case <-e.ctx.Done():
				e.log.Info("shutdown:", zap.Error(e.ctx.Err()))
				return
			case <-time.After(15 * time.Second):
				continue // check again
			}
		}

		results := make([]HostScan, len(batch))
		for i, host := range batch {
			e.wg.Add(1)
			go func(i int, host Host) {
				defer e.wg.Done()

				var err error
				if len(host.V2NetAddresses) > 0 {
					results[i], err = e.scanV2Host(locator, host)
				} else {
					results[i], err = e.scanV1Host(locator, host)
				}
				if err != nil {
					e.log.Debug("host scan failed", zap.Stringer("pk", host.PublicKey), zap.Error(err))
					results[i] = HostScan{
						PublicKey: host.PublicKey,
						Success:   false,
						Timestamp: types.CurrentTimestamp(),
					}
					return
				}
			}(i, host)
		}
		e.wg.Wait()

		if err := e.s.AddHostScans(e.scanCfg.MaxLastScan, results); err != nil {
			e.log.Info("failed to add host scans to DB:", zap.Error(err))
			return
		}
	}
}
