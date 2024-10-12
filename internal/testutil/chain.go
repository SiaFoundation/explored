package testutil

import (
	"math/bits"
	"time"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils"
	"go.sia.tech/coreutils/chain"
)

// ContractFilesize is the default file size of contracts formed with PrepareContractFormation.
const ContractFilesize = 10

// PrepareContractFormation creates a file contract using the specified
// renter/host keys, payouts, and start/end window.  It is an easier to
// use version of rhp2.PrepareContractFormation because it doesn't require
// a host settings struct and sets a default file size.
func PrepareContractFormation(renterPubKey types.PublicKey, hostKey types.PublicKey, renterPayout, hostCollateral types.Currency, startHeight uint64, endHeight uint64, refundAddr types.Address) types.FileContract {
	taxAdjustedPayout := func(target types.Currency) types.Currency {
		guess := target.Mul64(1000).Div64(961)
		mod64 := func(c types.Currency, v uint64) types.Currency {
			var r uint64
			if c.Hi < v {
				_, r = bits.Div64(c.Hi, c.Lo, v)
			} else {
				_, r = bits.Div64(0, c.Hi, v)
				_, r = bits.Div64(r, c.Lo, v)
			}
			return types.NewCurrency64(r)
		}
		sfc := (consensus.State{}).SiafundCount()
		tm := mod64(target, sfc)
		gm := mod64(guess, sfc)
		if gm.Cmp(tm) < 0 {
			guess = guess.Sub(types.NewCurrency64(sfc))
		}
		return guess.Add(tm).Sub(gm)
	}
	uc := types.UnlockConditions{
		PublicKeys: []types.UnlockKey{
			renterPubKey.UnlockKey(),
			hostKey.UnlockKey(),
		},
		SignaturesRequired: 2,
	}
	hostPayout := hostCollateral
	payout := taxAdjustedPayout(renterPayout.Add(hostPayout))
	return types.FileContract{
		Filesize:       ContractFilesize,
		FileMerkleRoot: types.Hash256{},
		WindowStart:    startHeight,
		WindowEnd:      endHeight,
		Payout:         payout,
		UnlockHash:     types.Hash256(uc.UnlockHash()),
		RevisionNumber: 0,
		ValidProofOutputs: []types.SiacoinOutput{
			{Value: renterPayout, Address: refundAddr},
			{Value: hostPayout, Address: types.VoidAddress},
		},
		MissedProofOutputs: []types.SiacoinOutput{
			{Value: renterPayout, Address: refundAddr},
			{Value: hostPayout, Address: types.VoidAddress},
			{Value: types.ZeroCurrency, Address: types.VoidAddress},
		},
	}
}

// CreateAnnouncement creates a host announcement.
func CreateAnnouncement(priv types.PrivateKey, netAddress string) []byte {
	return chain.HostAnnouncement{
		PublicKey:  priv.PublicKey(),
		NetAddress: netAddress,
	}.ToArbitraryData(priv)
}

// MineBlock mines sets the metadata fields of the block along with the
// transactions and then generates a valid nonce for the block.
func MineBlock(state consensus.State, txns []types.Transaction, minerAddr types.Address) types.Block {
	b := types.Block{
		ParentID:     state.Index.ID,
		Timestamp:    types.CurrentTimestamp(),
		Transactions: txns,
		MinerPayouts: []types.SiacoinOutput{{Address: minerAddr, Value: state.BlockReward()}},
	}
	if !coreutils.FindBlockNonce(state, &b, time.Minute) {
		panic("failed to mine test block quickly enough")
	}
	return b
}

// MineV2Block mines sets the metadata fields of the block along with the
// transactions and then generates a valid nonce for the block.
func MineV2Block(state consensus.State, txns []types.V2Transaction, minerAddr types.Address) types.Block {
	b := types.Block{
		ParentID:     state.Index.ID,
		Timestamp:    types.CurrentTimestamp(),
		MinerPayouts: []types.SiacoinOutput{{Address: minerAddr, Value: state.BlockReward()}},

		V2: &types.V2BlockData{
			Transactions: txns,
			Height:       state.Index.Height + 1,
		},
	}
	b.V2.Commitment = state.Commitment(state.TransactionsCommitment(b.Transactions, b.V2Transactions()), b.MinerPayouts[0].Address)
	for b.ID().CmpWork(state.ChildTarget) < 0 {
		b.Nonce += state.NonceFactor()
	}
	return b
}

// SignTransactionWithContracts signs a transaction using the specified private
// keys, including contract revisions.
func SignTransactionWithContracts(cs consensus.State, pk, renterPK, hostPK types.PrivateKey, txn *types.Transaction) {
	appendSig := func(key types.PrivateKey, pubkeyIndex uint64, parentID types.Hash256) {
		sig := key.SignHash(cs.WholeSigHash(*txn, parentID, pubkeyIndex, 0, nil))
		txn.Signatures = append(txn.Signatures, types.TransactionSignature{
			ParentID:       parentID,
			CoveredFields:  types.CoveredFields{WholeTransaction: true},
			PublicKeyIndex: pubkeyIndex,
			Signature:      sig[:],
		})
	}
	for i := range txn.SiacoinInputs {
		appendSig(pk, 0, types.Hash256(txn.SiacoinInputs[i].ParentID))
	}
	for i := range txn.SiafundInputs {
		appendSig(pk, 0, types.Hash256(txn.SiafundInputs[i].ParentID))
	}
	for i := range txn.FileContractRevisions {
		appendSig(renterPK, 0, types.Hash256(txn.FileContractRevisions[i].ParentID))
		appendSig(hostPK, 1, types.Hash256(txn.FileContractRevisions[i].ParentID))
	}
}

// SignTransaction signs a transaction that does not have any revisions with
// the specified private key.
func SignTransaction(cs consensus.State, pk types.PrivateKey, txn *types.Transaction) {
	if len(txn.FileContractRevisions) > 0 {
		panic("use SignTransactionWithContracts instead")
	}
	SignTransactionWithContracts(cs, pk, types.PrivateKey{}, types.PrivateKey{}, txn)
}
