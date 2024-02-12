package explorerutil

import (
	"errors"
	"fmt"
	"math/bits"
	"os"
	"path/filepath"

	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/chain"
)

type HashStore struct {
	hashFiles [64]*os.File
	numLeaves uint64
}

const hashSize = 32

type consensusUpdate interface {
	ForEachSiacoinElement(fn func(sce types.SiacoinElement, spent bool))
	ForEachSiafundElement(fn func(sfe types.SiafundElement, spent bool))
	ForEachFileContractElement(fn func(fce types.FileContractElement, rev *types.FileContractElement, resolved, valid bool))
}

func (hs *HashStore) updateLeaves(update consensusUpdate) error {
	var err error
	update.ForEachSiacoinElement(func(sce types.SiacoinElement, spent bool) {
		if err != nil {
			return
		}
		err = hs.ModifyLeaf(sce.StateElement)
		return
	})
	if err != nil {
		return err
	}

	update.ForEachSiafundElement(func(sce types.SiafundElement, spent bool) {
		if err != nil {
			return
		}
		err = hs.ModifyLeaf(sce.StateElement)
		return
	})
	if err != nil {
		return err
	}

	update.ForEachFileContractElement(func(sce types.FileContractElement, rev *types.FileContractElement, resolved, valid bool) {
		if err != nil {
			return
		}
		err = hs.ModifyLeaf(sce.StateElement)
		return
	})
	if err != nil {
		return err
	}

	return nil
}

// ProcessChainApplyUpdate implements chain.Subscriber.
func (hs *HashStore) ProcessChainApplyUpdate(cau *chain.ApplyUpdate, mayCommit bool) error {
	if err := hs.updateLeaves(cau); err != nil {
		return err
	}
	if mayCommit {
		return hs.Commit()
	}
	return nil
}

// ProcessChainRevertUpdate implements chain.Subscriber.
func (hs *HashStore) ProcessChainRevertUpdate(cru *chain.RevertUpdate) error {
	if err := hs.updateLeaves(cru); err != nil {
		return err
	}
	return hs.Commit()
}

// MerkleProof implements explorer.HashStore.
func (hs *HashStore) MerkleProof(leafIndex uint64) ([]types.Hash256, error) {
	pos := leafIndex
	proof := make([]types.Hash256, bits.Len64(leafIndex^hs.numLeaves)-1)
	for i := range proof {
		subtreeSize := uint64(1 << i)
		if leafIndex&(1<<i) == 0 {
			pos += subtreeSize
		} else {
			pos -= subtreeSize
		}
		if _, err := hs.hashFiles[i].ReadAt(proof[i][:], int64(pos/subtreeSize)*hashSize); err != nil {
			return nil, err
		}
	}
	return proof, nil
}

// ModifyLeaf implements explorer.HashStore.
func (hs *HashStore) ModifyLeaf(elem types.StateElement) error {
	pos := elem.LeafIndex
	for i, h := range elem.MerkleProof {
		n := uint64(1 << i)
		subtreeSize := uint64(1 << i)
		if elem.LeafIndex&(1<<i) == 0 {
			pos += subtreeSize
		} else {
			pos -= subtreeSize
		}
		if _, err := hs.hashFiles[i].WriteAt(h[:], int64(pos/n)*hashSize); err != nil {
			return err
		}
	}
	if elem.LeafIndex+1 > hs.numLeaves {
		hs.numLeaves = elem.LeafIndex + 1
	}
	return nil
}

// Commit implements explorer.HashStore.
func (hs *HashStore) Commit() error {
	for _, f := range hs.hashFiles {
		if err := f.Sync(); err != nil {
			return err
		}
	}
	return nil
}

// NewHashStore returns a new HashStore.
func NewHashStore(dir string) (*HashStore, error) {
	var hs HashStore
	for i := range hs.hashFiles {
		f, err := os.OpenFile(filepath.Join(dir, fmt.Sprintf("tree_level_%d.dat", i)), os.O_CREATE|os.O_RDWR, 0666)
		if err != nil {
			return nil, err
		}
		stat, err := f.Stat()
		if err != nil {
			return nil, err
		} else if stat.Size()%hashSize != 0 {
			// TODO: attempt to repair automatically
			return nil, errors.New("tree contains a partially-written hash")
		}
		if i == 0 {
			hs.numLeaves = uint64(stat.Size()) / hashSize
		}
		hs.hashFiles[i] = f
	}
	return &hs, nil
}
