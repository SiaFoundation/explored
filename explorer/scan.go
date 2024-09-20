package explorer

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	crhpv2 "go.sia.tech/core/rhp/v2"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/chain"
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

func (e *Explorer) scanHost(host chain.HostAnnouncement) (HostScan, error) {
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
		Timestamp: types.CurrentTimestamp(),

		Settings:   settings,
		PriceTable: table,
	}, nil
}

func (e *Explorer) addHostScans(hosts chan chain.HostAnnouncement) {
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
					Timestamp: types.CurrentTimestamp(),
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
	var wg sync.WaitGroup
	for t := 0; t < e.scanCfg.Threads; t++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			worker()
		}()
	}

	// wait until they're done
	wg.Wait()
}

func (e *Explorer) isClosed() bool {
	select {
	case <-e.ctx.Done():
		return true
	default:
		return false
	}
}

func (e *Explorer) fetchHosts(hosts chan chain.HostAnnouncement) {
	var exhausted bool
	offset := 0

	t := types.CurrentTimestamp()
	cutoff := t.Add(-e.scanCfg.MaxLastScan)
	lastAnnouncement := t.Add(-e.scanCfg.MinLastAnnouncement)

	for !exhausted && !e.isClosed() {
		batch, err := e.s.HostsForScanning(cutoff, lastAnnouncement, uint64(offset), scanBatchSize)
		if err != nil {
			e.log.Error("failed to get hosts for scanning", zap.Error(err))
			return
		} else if len(batch) < scanBatchSize {
			exhausted = true
		}

		for _, host := range batch {
			select {
			case <-e.ctx.Done():
				return
			case hosts <- host:
			}
		}
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
		// fetch hosts
		hosts := make(chan chain.HostAnnouncement, scanBatchSize)
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			e.fetchHosts(hosts)
			close(hosts)
		}()

		// scan hosts
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			e.addHostScans(hosts)
		}()

		// wait for scans to complete
		waitChan := make(chan struct{})
		go func() {
			e.wg.Wait()
			close(waitChan)
		}()
		select {
		case <-waitChan:
		case <-e.ctx.Done():
			return
		}

		// pause
		select {
		case <-e.ctx.Done():
			return
		case <-time.After(30 * time.Second):
		}
	}
}
