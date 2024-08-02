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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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

func (e *Explorer) scanHosts() {
	const (
		scanBatchSize   = 100
		scanMinInterval = 3 * time.Hour
	)

	// don't scan hosts till we're at least nearly done with syncing
	e.waitForSync()

	for {
		offset := uint64(0)
		cutoff := time.Now().Add(-scanMinInterval)
		for {
			hosts, err := e.s.HostsForScanning(cutoff, offset, scanBatchSize)
			if err != nil {
				e.log.Error("failed to get hosts for scanning", zap.Error(err))
			}

			offset += uint64(len(hosts))
			if len(hosts) < scanBatchSize {
				break
			}

			var scanned []Host
			for _, host := range hosts {
				if scan, err := e.scanHost(host); err != nil {
					e.log.Error("failed to scan host", zap.Error(err))
				} else {
					scanned = append(scanned, scan)
				}
			}

			if err := e.s.AddHostScans(scanned); err != nil {
				e.log.Error("failed to add host sacns", zap.Error(err))
			}
		}
	}
}
