package sqlite

import (
	"database/sql"
	"errors"
	"fmt"

	"go.sia.tech/core/chain"
	"go.sia.tech/core/types"
	"go.sia.tech/explored/explorer"
)

func (s *Store) addBlock(dbTxn txn, b types.Block, height uint64) error {
	// nonce is encoded because database/sql doesn't support uint64 with high bit set
	_, err := dbTxn.Exec("INSERT INTO blocks(id, height, parent_id, nonce, timestamp) VALUES (?, ?, ?, ?, ?);", dbEncode(b.ID()), height, dbEncode(b.ParentID), dbEncode(b.Nonce), dbEncode(b.Timestamp))
	return err
}

func (s *Store) addMinerPayouts(dbTxn txn, bid types.BlockID, height uint64, scos []types.SiacoinOutput, dbIDs map[types.SiacoinOutputID]int64) error {
	stmt, err := dbTxn.Prepare(`INSERT INTO miner_payouts(block_id, block_order, output_id) VALUES (?, ?, ?);`)
	if err != nil {
		return fmt.Errorf("addMinerPayouts: failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for i := range scos {
		dbID, ok := dbIDs[bid.MinerOutputID(i)]
		if !ok {
			return errors.New("addMinerPayouts: dbID not in map")
		}

		if _, err := stmt.Exec(dbEncode(bid), i, dbID); err != nil {
			return fmt.Errorf("addMinerPayouts: failed to execute statement: %w", err)
		}
	}
	return nil
}

func (s *Store) addArbitraryData(dbTxn txn, id int64, txn types.Transaction) error {
	stmt, err := dbTxn.Prepare(`INSERT INTO transaction_arbitrary_data(transaction_id, transaction_order, data) VALUES (?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("addArbitraryData: failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for i, arbitraryData := range txn.ArbitraryData {
		if _, err := stmt.Exec(id, i, arbitraryData); err != nil {
			return fmt.Errorf("addArbitraryData: failed to execute statement: %w", err)
		}
	}
	return nil
}

func (s *Store) addSiacoinInputs(dbTxn txn, id int64, txn types.Transaction) error {
	stmt, err := dbTxn.Prepare(`INSERT INTO transaction_siacoin_inputs(transaction_id, transaction_order, parent_id, unlock_conditions) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("addSiacoinInputs: failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for i, sci := range txn.SiacoinInputs {
		if _, err := stmt.Exec(id, i, dbEncode(sci.ParentID), dbEncode(sci.UnlockConditions)); err != nil {
			return fmt.Errorf("addSiacoinInputs: failed to execute statement: %w", err)
		}
	}
	return nil
}

func (s *Store) addSiacoinOutputs(dbTxn txn, id int64, txn types.Transaction, dbIDs map[types.SiacoinOutputID]int64) error {
	stmt, err := dbTxn.Prepare(`INSERT INTO transaction_siacoin_outputs(transaction_id, transaction_order, output_id) VALUES (?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("addSiacoinOutputs: failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for i := range txn.SiacoinOutputs {
		dbID, ok := dbIDs[txn.SiacoinOutputID(i)]
		if !ok {
			return errors.New("addSiacoinOutputs: dbID not in map")
		}

		if _, err := stmt.Exec(id, i, dbID); err != nil {
			return fmt.Errorf("addSiacoinOutputs: failed to execute statement: %w", err)
		}
	}
	return nil
}

func (s *Store) addSiafundInputs(dbTxn txn, id int64, txn types.Transaction) error {
	stmt, err := dbTxn.Prepare(`INSERT INTO transaction_siafund_inputs(transaction_id, transaction_order, parent_id, unlock_conditions, claim_address) VALUES (?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("addSiafundInputs: failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for i, sci := range txn.SiafundInputs {
		if _, err := stmt.Exec(id, i, dbEncode(sci.ParentID), dbEncode(sci.UnlockConditions), dbEncode(sci.ClaimAddress)); err != nil {
			return fmt.Errorf("addSiafundInputs: failed to execute statement: %w", err)
		}
	}
	return nil
}

func (s *Store) addSiafundOutputs(dbTxn txn, id int64, txn types.Transaction, dbIDs map[types.SiafundOutputID]int64) error {
	stmt, err := dbTxn.Prepare(`INSERT INTO transaction_siafund_outputs(transaction_id, transaction_order, output_id) VALUES (?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("addSiafundOutputs: failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for i := range txn.SiafundOutputs {
		dbID, ok := dbIDs[txn.SiafundOutputID(i)]
		if !ok {
			return errors.New("addSiafundOutputs: dbID not in map")
		}

		if _, err := stmt.Exec(id, i, dbID); err != nil {
			return fmt.Errorf("addSiafundOutputs: failed to execute statement: %w", err)
		}
	}
	return nil
}

func (s *Store) addTransactions(dbTxn txn, bid types.BlockID, txns []types.Transaction, scDBIds map[types.SiacoinOutputID]int64, sfDBIds map[types.SiafundOutputID]int64) error {
	insertTransactionStmt, err := dbTxn.Prepare(`INSERT INTO transactions (transaction_id) VALUES (?)
	ON CONFLICT (transaction_id) DO UPDATE SET transaction_id=EXCLUDED.transaction_id -- technically a no-op, but necessary for the RETURNING clause
	RETURNING id;`)
	if err != nil {
		return fmt.Errorf("failed to prepare insert transaction statement: %v", err)
	}
	defer insertTransactionStmt.Close()

	blockTransactionsStmt, err := dbTxn.Prepare(`INSERT INTO block_transactions(block_id, transaction_id, block_order) VALUES (?, ?, ?);`)
	if err != nil {
		return fmt.Errorf("failed to prepare block_transactions statement: %w", err)
	}
	defer blockTransactionsStmt.Close()

	for i, txn := range txns {
		var txnID int64
		err := insertTransactionStmt.QueryRow(dbEncode(txn.ID())).Scan(&txnID)
		if err != nil {
			return fmt.Errorf("failed to insert into transactions: %w", err)
		}

		if _, err := blockTransactionsStmt.Exec(dbEncode(bid), txnID, i); err != nil {
			return fmt.Errorf("failed to insert into block_transactions: %w", err)
		} else if err := s.addArbitraryData(dbTxn, txnID, txn); err != nil {
			return fmt.Errorf("failed to add arbitrary data: %w", err)
		} else if err := s.addSiacoinInputs(dbTxn, txnID, txn); err != nil {
			return fmt.Errorf("failed to add siacoin inputs: %w", err)
		} else if err := s.addSiacoinOutputs(dbTxn, txnID, txn, scDBIds); err != nil {
			return fmt.Errorf("failed to add siacoin outputs: %w", err)
		} else if err := s.addSiafundInputs(dbTxn, txnID, txn); err != nil {
			return fmt.Errorf("failed to add siafund inputs: %w", err)
		} else if err := s.addSiafundOutputs(dbTxn, txnID, txn, sfDBIds); err != nil {
			return fmt.Errorf("failed to add siafund outputs: %w", err)
		}
	}
	return nil
}

type consensusUpdate interface {
	ForEachSiacoinElement(fn func(sce types.SiacoinElement, spent bool))
	ForEachSiafundElement(fn func(sfe types.SiafundElement, spent bool))
}

func (s *Store) updateBalances(dbTxn txn, update consensusUpdate) error {
	type balance struct {
		sc types.Currency
		sf uint64
	}

	addresses := make(map[types.Address]balance)
	update.ForEachSiacoinElement(func(sce types.SiacoinElement, spent bool) {
		addresses[sce.SiacoinOutput.Address] = balance{}
	})
	update.ForEachSiafundElement(func(sfe types.SiafundElement, spent bool) {
		addresses[sfe.SiafundOutput.Address] = balance{}
	})

	var addressList []any
	for address := range addresses {
		addressList = append(addressList, dbEncode(address))
	}

	rows, err := dbTxn.Query(`SELECT address, siacoin_balance, siafund_balance
		FROM address_balance
		WHERE address IN (`+queryPlaceHolders(len(addressList))+`)`, queryArgs(addressList)...)
	if err != nil {
		return fmt.Errorf("updateBalances: failed to query address_balance: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var address types.Address
		var sc types.Currency
		var sf uint64
		if err := rows.Scan(dbDecode(&address), dbDecode(&sc), dbDecode(&sf)); err != nil {
			return err
		}
		addresses[address] = balance{
			sc: sc,
			sf: sf,
		}
	}

	// log.Println("New block")
	update.ForEachSiacoinElement(func(sce types.SiacoinElement, spent bool) {
		bal := addresses[sce.SiacoinOutput.Address]
		if spent {
			// If within the same block, an address A receives SC in one
			// transaction and sends it to another address in a later
			// transaction, the chain update will not contain the unspent
			// siacoin element that was temporarily A's. This can then result
			// in underflow when we subtract the element for A as being spent.
			// So we catch underflow here because this causes crashes even
			// though there is no net balance change for A.
			// Example: https://siascan.com/block/506

			// log.Println("Spend:", sce.SiacoinOutput.Address, sce.SiacoinOutput.Value)
			underflow := false
			bal.sc, underflow = bal.sc.SubWithUnderflow(sce.SiacoinOutput.Value)
			if underflow {
				return
			}
		} else {
			// log.Println("Gain:", sce.SiacoinOutput.Address, sce.SiacoinOutput.Value)
			bal.sc = bal.sc.Add(sce.SiacoinOutput.Value)
		}
		addresses[sce.SiacoinOutput.Address] = bal
	})
	update.ForEachSiafundElement(func(sfe types.SiafundElement, spent bool) {
		bal := addresses[sfe.SiafundOutput.Address]
		if spent {
			underflow := (bal.sf - sfe.SiafundOutput.Value) > bal.sf
			if underflow {
				return
			}
			bal.sf -= sfe.SiafundOutput.Value
		} else {
			bal.sf += sfe.SiafundOutput.Value
		}
		addresses[sfe.SiafundOutput.Address] = bal
	})

	stmt, err := dbTxn.Prepare(`INSERT INTO address_balance(address, siacoin_balance, siafund_balance)
	VALUES (?, ?, ?)
	ON CONFLICT(address)
	DO UPDATE set siacoin_balance = ?, siafund_balance = ?`)
	if err != nil {
		return fmt.Errorf("updateBalances: failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for addr, bal := range addresses {
		if _, err := stmt.Exec(dbEncode(addr), dbEncode(bal.sc), dbEncode(bal.sf), dbEncode(bal.sc), dbEncode(bal.sf)); err != nil {
			return fmt.Errorf("updateBalances: failed to exec statement: %w", err)
		}
		// log.Println(addr, "=", bal.sc)
	}

	return nil
}

func (s *Store) addSCOutputs(dbTxn txn, update consensusUpdate) (map[types.SiacoinOutputID]int64, error) {
	sources := make(map[types.SiacoinOutputID]explorer.Source)
	if applyUpdate, ok := update.(*chain.ApplyUpdate); ok {
		block := applyUpdate.Block
		for i := range block.MinerPayouts {
			sources[block.ID().MinerOutputID(i)] = explorer.SourceMinerPayout
		}
		for _, txn := range block.Transactions {
			for i := range txn.SiacoinOutputs {
				sources[txn.SiacoinOutputID(i)] = explorer.SourceTransaction
			}
			// TODO: contract valid/missed outputs
		}
	}

	stmt, err := dbTxn.Prepare(`INSERT INTO siacoin_outputs(output_id, spent, source, maturity_height, address, value)
			VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT(output_id)
			DO UPDATE SET spent = ?`)
	if err != nil {
		return nil, fmt.Errorf("addSCOutputs: failed to prepare siacoin_outputs statement: %w", err)
	}
	defer stmt.Close()

	var updateErr error
	scDBIds := make(map[types.SiacoinOutputID]int64)
	update.ForEachSiacoinElement(func(sce types.SiacoinElement, spent bool) {
		if updateErr != nil {
			return
		}

		result, err := stmt.Exec(dbEncode(sce.StateElement.ID), spent, int(sources[types.SiacoinOutputID(sce.StateElement.ID)]), sce.MaturityHeight, dbEncode(sce.SiacoinOutput.Address), dbEncode(sce.SiacoinOutput.Value), spent)
		if err != nil {
			updateErr = fmt.Errorf("addSCOutputs: failed to execute siacoin_outputs statement: %w", err)
			return
		}

		dbID, err := result.LastInsertId()
		if err != nil {
			updateErr = fmt.Errorf("addSCOutputs: failed to get last insert ID: %w", err)
			return
		}

		scDBIds[types.SiacoinOutputID(sce.StateElement.ID)] = dbID
	})
	return scDBIds, updateErr
}

func (s *Store) addSFOutputs(dbTxn txn, update consensusUpdate) (map[types.SiafundOutputID]int64, error) {
	stmt, err := dbTxn.Prepare(`INSERT INTO siafund_outputs(output_id, spent, claim_start, address, value)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(output_id)
		DO UPDATE SET spent = ?`)
	if err != nil {
		return nil, fmt.Errorf("addSFOutputs: failed to prepare siafund_outputs statement: %w", err)
	}
	defer stmt.Close()

	var updateErr error
	sfDBIds := make(map[types.SiafundOutputID]int64)
	update.ForEachSiafundElement(func(sfe types.SiafundElement, spent bool) {
		if updateErr != nil {
			return
		}

		result, err := stmt.Exec(dbEncode(sfe.StateElement.ID), spent, dbEncode(sfe.ClaimStart), dbEncode(sfe.SiafundOutput.Address), dbEncode(sfe.SiafundOutput.Value), spent)
		if err != nil {
			updateErr = fmt.Errorf("addSFOutputs: failed to execute siafund_outputs statement: %w", err)
			return
		}

		dbID, err := result.LastInsertId()
		if err != nil {
			updateErr = fmt.Errorf("addSFOutputs: failed to get last insert ID: %w", err)
			return
		}

		sfDBIds[types.SiafundOutputID(sfe.StateElement.ID)] = dbID
	})
	return sfDBIds, updateErr
}

func (s *Store) deleteBlock(dbTxn txn, bid types.BlockID) error {
	_, err := dbTxn.Exec("DELETE FROM blocks WHERE id = ?", dbEncode(bid))
	return err
}

func (s *Store) applyUpdates() error {
	return s.transaction(func(dbTxn txn) error {
		for _, update := range s.pendingUpdates {
			scDBIds, err := s.addSCOutputs(dbTxn, update)
			if err != nil {
				return fmt.Errorf("applyUpdates: failed to add siacoin outputs: %w", err)
			}
			sfDBIds, err := s.addSFOutputs(dbTxn, update)
			if err != nil {
				return fmt.Errorf("applyUpdates: failed to add siafund outputs: %w", err)
			}
			if err := s.updateBalances(dbTxn, update); err != nil {
				return fmt.Errorf("applyUpdates: failed to update balances: %w", err)
			}

			if err := s.addBlock(dbTxn, update.Block, update.State.Index.Height); err != nil {
				return fmt.Errorf("applyUpdates: failed to add block: %w", err)
			} else if err := s.addMinerPayouts(dbTxn, update.Block.ID(), update.State.Index.Height, update.Block.MinerPayouts, scDBIds); err != nil {
				return fmt.Errorf("applyUpdates: failed to add miner payouts: %w", err)
			} else if err := s.addTransactions(dbTxn, update.Block.ID(), update.Block.Transactions, scDBIds, sfDBIds); err != nil {
				return fmt.Errorf("applyUpdates: failed to add transactions: addTransactions: %w", err)
			}
		}
		s.pendingUpdates = s.pendingUpdates[:0]
		return nil
	})
}

func (s *Store) revertUpdate(cru *chain.RevertUpdate) error {
	return s.transaction(func(dbTxn txn) error {
		if err := s.deleteBlock(dbTxn, cru.Block.ID()); err != nil {
			return fmt.Errorf("revertUpdate: failed to delete block: %w", err)
		} else if _, err := s.addSCOutputs(dbTxn, cru); err != nil {
			return fmt.Errorf("revertUpdate: failed to update siacoin output state: %w", err)
		} else if _, err := s.addSFOutputs(dbTxn, cru); err != nil {
			return fmt.Errorf("revertUpdate: failed to update siafund output state: %w", err)
		} else if err := s.updateBalances(dbTxn, cru); err != nil {
			return fmt.Errorf("revertUpdate: failed to update balances: %w", err)
		}
		return nil
	})
}

// ProcessChainApplyUpdate implements chain.Subscriber.
func (s *Store) ProcessChainApplyUpdate(cau *chain.ApplyUpdate, mayCommit bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.pendingUpdates = append(s.pendingUpdates, cau)
	if mayCommit {
		return s.applyUpdates()
	}
	return nil
}

// ProcessChainRevertUpdate implements chain.Subscriber.
func (s *Store) ProcessChainRevertUpdate(cru *chain.RevertUpdate) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.pendingUpdates) > 0 && s.pendingUpdates[len(s.pendingUpdates)-1].Block.ID() == cru.Block.ID() {
		s.pendingUpdates = s.pendingUpdates[:len(s.pendingUpdates)-1]
		return nil
	}
	return s.revertUpdate(cru)
}

// Tip implements explorer.Store.
func (s *Store) Tip() (result types.ChainIndex, err error) {
	const query = `SELECT id, height FROM blocks ORDER BY height DESC LIMIT 1`
	err = s.transaction(func(dbTx txn) error {
		return dbTx.QueryRow(query).Scan(dbDecode(&result.ID), &result.Height)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return types.ChainIndex{}, ErrNoTip
	}
	return
}
