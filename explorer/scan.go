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

func (e *Explorer) waitForSync() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		cs := e.cm.TipState()
		if cs.PrevTimestamps[0].After(time.Now().Add(-time.Hour)) {
			break
		}

		select {
		case <-ticker.C:
			continue
		}
	}
}

func (e *Explorer) scanHost(host HostAnnouncement) (Host, error) {
	e.log.Debug("Scanning host", zap.String("addr", host.NetAddress), zap.String("pk", host.PublicKey.String()))

	ctx, cancel := context.WithTimeout(context.Background(), e.scanCfg.Timeout)
	defer cancel()

	dialer := (&net.Dialer{})
	conn, err := dialer.DialContext(ctx, "tcp", host.NetAddress)
	if err != nil {
		return Host{}, fmt.Errorf("scanHost: failed to connect to host: %w", err)
	}
	defer conn.Close()

	transport, err := crhpv2.NewRenterTransport(conn, host.PublicKey)
	if err != nil {
		return Host{}, fmt.Errorf("scanHost: failed to establish v2 transport: %w", err)
	}
	defer transport.Close()

	settings, err := rhpv2.RPCSettings(ctx, transport)
	if err != nil {
		return Host{}, fmt.Errorf("scanHost: failed to get host settings: %w", err)
	}

	hostIP, _, err := net.SplitHostPort(settings.NetAddress)
	if err != nil {
		return Host{}, fmt.Errorf("scanHost: failed to parse net address: %w", err)
	}

	v3Addr := net.JoinHostPort(hostIP, settings.SiaMuxPort)
	v3Session, err := rhpv3.NewSession(ctx, host.PublicKey, v3Addr, e.cm, nil)
	if err != nil {
		return Host{}, fmt.Errorf("scanHost: failed to establish v3 transport: %w", err)
	}

	table, err := v3Session.ScanPriceTable()
	if err != nil {
		return Host{}, fmt.Errorf("scanHost: failed to scan price table: %w", err)
	}

	return Host{
		PublicKey:  host.PublicKey,
		NetAddress: host.NetAddress,

		Settings:   settings,
		PriceTable: table,

		LastScan:               time.Now(),
		TotalScans:             1,
		SuccessfulInteractions: 1,
	}, nil
}

func (e *Explorer) scanThread(req chan HostAnnouncement, resp chan Host) {
	for host := range req {
		if scan, err := e.scanHost(host); err != nil {
			resp <- Host{
				PublicKey:  host.PublicKey,
				NetAddress: host.NetAddress,

				LastScan:           time.Now(),
				TotalScans:         1,
				FailedInteractions: 1,
			}
			e.log.Info("failed to scan host", zap.String("addr", host.NetAddress), zap.String("pk", host.PublicKey.String()), zap.Error(err))
		} else {
			resp <- scan
		}
	}
}

func (e *Explorer) scanHosts() {
	const (
		scanBatchSize = 100
	)

	e.log.Info("Waiting for syncing to complete before scanning hosts")
	// don't scan hosts till we're at least nearly done with syncing
	e.waitForSync()
	e.log.Info("Syncing complete, will begin scanning hosts")

	announcements := make(chan HostAnnouncement)
	scans := make(chan Host)

	for i := 0; i < e.scanCfg.Threads; i++ {
		go e.scanThread(announcements, scans)
	}
	for {
		offset := uint64(0)
		cutoff := time.Now().Add(-e.scanCfg.MaxLastScan)
		for {
			hosts, err := e.s.HostsForScanning(cutoff, offset, scanBatchSize)
			if err != nil {
				e.log.Error("failed to get hosts for scanning", zap.Error(err))
			}
			offset += uint64(len(hosts))

			for _, host := range hosts {
				announcements <- host
			}

			if len(hosts) < scanBatchSize {
				break
			}
		}

		var scanned []Host
		for scan := range scans {
			scanned = append(scanned, scan)
			if uint64(len(scanned)) == offset {
				break
			}
		}

		if err := e.s.AddHostScans(scanned); err != nil {
			e.log.Error("failed to add host scans", zap.Error(err))
		}
		e.log.Debug("Added all scans to DB", zap.Int("count", len(scanned)))
	}
}
