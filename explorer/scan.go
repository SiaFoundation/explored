package explorer

import (
	"context"
	"fmt"
	"net"
	"time"

	crhpv2 "go.sia.tech/core/rhp/v2"
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

func (e *Explorer) scanHost(host HostAnnouncement) (HostScan, error) {
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
		PublicKey: host.PublicKey,
		Success:   true,
		Timestamp: time.Now(),

		Settings:   settings,
		PriceTable: table,
	}, nil
}

func (e *Explorer) addHostScans(hosts chan HostAnnouncement) {
	worker := func() {
		var scans []HostScan
		for host := range hosts {
			if e.isClosed() {
				break
			}

			scan, err := e.scanHost(host)
			if err != nil {
				scans = append(scans, HostScan{
					PublicKey: host.PublicKey,
					Success:   false,
					Timestamp: time.Now(),
				})
				e.log.Debug("Scanning host failed", zap.String("addr", host.NetAddress), zap.Stringer("pk", host.PublicKey), zap.Error(err))
				continue
			}

			e.log.Debug("Scanning host succeeded", zap.String("addr", host.NetAddress), zap.Stringer("pk", host.PublicKey))
			scans = append(scans, scan)
		}

		if err := e.s.AddHostScans(scans); err != nil {
			e.log.Error("Failed to add host scans to DB", zap.Error(err))
		}
	}

	// launch all workers
	for t := 0; t < e.scanCfg.Threads; t++ {
		e.wg.Add(1)
		go func() {
			worker()
			e.wg.Done()
		}()
	}

	// wait until they're done
	e.wg.Wait()
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

	for !e.isClosed() {
		offset := 0
		cutoff := time.Now().Add(-e.scanCfg.MaxLastScan)

		announcements := make(chan HostAnnouncement)

		go func() {
			defer close(announcements)
			for !e.isClosed() {
				hosts, err := e.s.HostsForScanning(cutoff, uint64(offset), scanBatchSize)
				if err != nil {
					e.log.Error("failed to get hosts for scanning", zap.Error(err))
					return
				}
				offset += len(hosts)

			LOOP:
				for _, host := range hosts {
					select {
					case <-e.ctx.Done():
						break LOOP
					case announcements <- host:
					}
				}

				if len(hosts) < scanBatchSize {
					break
				}
			}
		}()

		e.addHostScans(announcements)
		select {
		case <-e.ctx.Done():
		case <-time.After(30 * time.Second):
		}
	}
}
