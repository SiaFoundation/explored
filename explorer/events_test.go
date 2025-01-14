package explorer_test

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/wallet"
	"go.sia.tech/explored/explorer"
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
			Type:          wallet.EventTypeV1Transaction,
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
			Type:          wallet.EventTypeV1ContractResolution,
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
			Type:          wallet.EventTypeV2ContractResolution,
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
			Type:          wallet.EventTypeV2Transaction,
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

		if event.ID != unmarshalled.ID {
			t.Errorf("ID: expected %v, got %v", event.ID, unmarshalled.ID)
		}
		if event.Index != unmarshalled.Index {
			t.Errorf("Index: expected %v, got %v", event.Index, unmarshalled.Index)
		}
		if event.Confirmations != unmarshalled.Confirmations {
			t.Errorf("Confirmations: expected %d, got %d", event.Confirmations, unmarshalled.Confirmations)
		}
		if event.Type != unmarshalled.Type {
			t.Errorf("Type: expected %s, got %s", event.Type, unmarshalled.Type)
		}
		if event.MaturityHeight != unmarshalled.MaturityHeight {
			t.Errorf("MaturityHeight: expected %d, got %d", event.MaturityHeight, unmarshalled.MaturityHeight)
		}
		if !event.Timestamp.Equal(unmarshalled.Timestamp) {
			t.Errorf("Timestamp: expected %v, got %v", event.Timestamp, unmarshalled.Timestamp)
		}
		if !reflect.DeepEqual(event.Relevant, unmarshalled.Relevant) {
			t.Errorf("Relevant: expected %v, got %v", event.Relevant, unmarshalled.Relevant)
		}
		if !reflect.DeepEqual(event.Data, unmarshalled.Data) {
			t.Errorf("Data: expected %v, got %v", event.Data, unmarshalled.Data)
		}
	}
}
