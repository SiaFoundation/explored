package explorer_test

import (
	"encoding/json"
	"testing"
	"time"

	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/wallet"
	"go.sia.tech/explored/explorer"
	"go.sia.tech/explored/internal/testutil"
)

func TestEventMarshalling(t *testing.T) {
	id := types.Hash256{31: 255}
	index := types.ChainIndex{Height: 10}
	timestamp := time.Now()
	address := types.Address{31: 255}

	sco := explorer.SiacoinOutput{
		SiacoinElement: types.SiacoinElement{
			SiacoinOutput: types.SiacoinOutput{
				Address: address,
				Value:   types.Siacoins(1),
			},
		},
	}

	events := []explorer.Event{
		{
			ID:            id,
			Index:         index,
			Confirmations: 10,
			Type:          wallet.EventTypeMinerPayout,
			Data: explorer.EventPayout{
				SiacoinElement: sco,
			},
			MaturityHeight: 100,
			Timestamp:      timestamp,
			Relevant:       []types.Address{address},
		},
		{
			ID:            id,
			Index:         index,
			Confirmations: 20,
			Type:          "v1Transaction",
			Data: explorer.EventV1Transaction{
				Transaction: explorer.Transaction{
					SiacoinOutputs: []explorer.SiacoinOutput{sco},
				},
			},
			MaturityHeight: 200,
			Timestamp:      timestamp,
			Relevant:       []types.Address{address},
		},
		{
			ID:            id,
			Index:         index,
			Confirmations: 30,
			Type:          "v1ContractResolution",
			Data: explorer.EventV1ContractResolution{
				SiacoinElement: sco,
				Missed:         true,
			},
			MaturityHeight: 300,
			Timestamp:      timestamp,
			Relevant:       []types.Address{address},
		},
		{
			ID:            id,
			Index:         index,
			Confirmations: 40,
			Type:          "v2ContractResolution",
			Data: explorer.EventV2ContractResolution{
				SiacoinElement: sco,
				Missed:         true,
			},
			MaturityHeight: 400,
			Timestamp:      timestamp,
			Relevant:       []types.Address{address},
		},
		{
			ID:            id,
			Index:         index,
			Confirmations: 50,
			Type:          "v2Transaction",
			Data: explorer.EventV2Transaction(explorer.V2Transaction{
				SiacoinOutputs: []explorer.SiacoinOutput{sco},
			}),
			MaturityHeight: 500,
			Timestamp:      timestamp,
			Relevant:       []types.Address{address},
		},
	}

	for _, event := range events {
		data, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}

		var unmarshalled explorer.Event
		if err := json.Unmarshal(data, &unmarshalled); err != nil {
			t.Fatal(err)
		}

		testutil.Equal(t, "ID", event.ID, unmarshalled.ID)
		testutil.Equal(t, "Index", event.Index, unmarshalled.Index)
		testutil.Equal(t, "Confirmations", event.Confirmations, unmarshalled.Confirmations)
		testutil.Equal(t, "Type", event.Type, unmarshalled.Type)
		testutil.Equal(t, "MaturityHeight", event.MaturityHeight, unmarshalled.MaturityHeight)
		testutil.Equal(t, "Timestamp", event.Timestamp, unmarshalled.Timestamp)
		testutil.Equal(t, "Relevant", event.Relevant, unmarshalled.Relevant)
		testutil.Equal(t, "Data", event.Data, unmarshalled.Data)
	}
}
