package explorer

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	crhpv2 "go.sia.tech/core/rhp/v2"
	rhpv2 "go.sia.tech/explored/internal/rhp/v2"
	rhpv3 "go.sia.tech/explored/internal/rhp/v3"
	"go.uber.org/zap"
)

func (e *Explorer) waitForSync(ctx context.Context) bool {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		cs := e.cm.TipState()
		if cs.PrevTimestamps[0].After(time.Now().Add(-time.Hour)) {
			break
		}

		select {
		case <-ctx.Done():
			return false
		case <-ticker.C:
			continue
		}
	}

	return true
}

func (e *Explorer) scanHost(host HostAnnouncement) (HostScan, error) {
	ctx, cancel := context.WithTimeout(context.Background(), e.scanCfg.Timeout)
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

func (e *Explorer) addHostScans(ctx context.Context, hosts chan HostAnnouncement) {
	worker := func() {
		var scans []HostScan
		for {
			select {
			case <-ctx.Done():
				e.log.Debug("Terminating worker early due to interrupt")
				break
			case host := <-hosts:
				scan, err := e.scanHost(host)
				if err != nil {
					scans = append(scans, HostScan{
						PublicKey: host.PublicKey,
						Success:   false,
						Timestamp: time.Now(),
					})
					e.log.Debug("Scanning host failed", zap.String("addr", host.NetAddress), zap.String("pk", host.PublicKey.String()), zap.Error(err))
					continue
				}

				e.log.Debug("Scanning host succeeded", zap.String("addr", host.NetAddress), zap.String("pk", host.PublicKey.String()))
				scans = append(scans, scan)
			}
		}

		if err := e.s.AddHostScans(scans); err != nil {
			e.log.Error("Failed to add host scans to DB", zap.Error(err))
		}
	}

	// launch all workers
	var wg sync.WaitGroup
	for t := 0; t < e.scanCfg.Threads; t++ {
		wg.Add(1)
		go func() {
			worker()
			wg.Done()
		}()
	}

	// wait until they're done
	wg.Wait()
}

func (e *Explorer) scanHosts(ctx context.Context) {
	const (
		scanBatchSize = 100
	)

	e.log.Info("Waiting for syncing to complete before scanning hosts")
	// don't scan hosts till we're at least nearly done with syncing
	if !e.waitForSync(ctx) {
		e.log.Info("Interrupted before syncing started")
		return
	}
	e.log.Info("Syncing complete, will begin scanning hosts")

	for ctx.Err() != nil {
		offset := 0
		cutoff := time.Now().Add(-e.scanCfg.MaxLastScan)

		announcements := make(chan HostAnnouncement)

		go func() {
			defer close(announcements)
			for ctx.Err() != nil {
				hosts, err := e.s.HostsForScanning(cutoff, uint64(offset), scanBatchSize)
				if err != nil {
					e.log.Error("failed to get hosts for scanning", zap.Error(err))
					return
				}
				offset += len(hosts)

				for _, host := range hosts {
					announcements <- host
				}

				if len(hosts) < scanBatchSize {
					break
				}
			}
		}()

		e.addHostScans(ctx, announcements)
	}
}
