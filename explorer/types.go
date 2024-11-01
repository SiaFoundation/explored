package explorer

import (
	"encoding/json"
	"errors"
	"time"

	"go.sia.tech/core/consensus"
	rhpv2 "go.sia.tech/core/rhp/v2"
	rhpv3 "go.sia.tech/core/rhp/v3"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/chain"
)

// A Source represents where a siacoin output came from.
type Source int

const (
	// SourceInvalid represents a source we are not aware of.
	SourceInvalid Source = iota
	// SourceMinerPayout means the source of the output is a miner payout.
	SourceMinerPayout
	// SourceTransaction means the source of the output is a transaction.
	SourceTransaction
	// SourceValidProofOutput me ans the source of the output is a valid proof
	// output.
	SourceValidProofOutput
	// SourceMissedProofOutput me ans the source of the output is a missed
	// proof output.
	SourceMissedProofOutput
)

// MarshalJSON implements json.Marshaler.
func (s Source) MarshalJSON() ([]byte, error) {
	sourceToString := map[Source]string{
		SourceInvalid:           "invalid",
		SourceMinerPayout:       "miner_payout",
		SourceTransaction:       "transaction",
		SourceValidProofOutput:  "valid_proof_output",
		SourceMissedProofOutput: "missed_proof_output",
	}

	str, ok := sourceToString[s]
	if !ok {
		str = "invalid" // "invalid" if source is unknown
	}
	return json.Marshal(str)
}

// UnmarshalJSON implements json.Unmarshaler.
func (s *Source) UnmarshalJSON(data []byte) error {
	stringToSource := map[string]Source{
		"invalid":             SourceInvalid,
		"miner_payout":        SourceMinerPayout,
		"transaction":         SourceTransaction,
		"valid_proof_output":  SourceValidProofOutput,
		"missed_proof_output": SourceMissedProofOutput,
	}

	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}

	source, ok := stringToSource[str]
	if !ok {
		return errors.New("invalid source type")
	}

	*s = source
	return nil
}

// A SearchType represents the type of element found during a search.
type SearchType string

const (
	// SearchTypeInvalid means we were unable to find any element with the
	// given identifier.
	SearchTypeInvalid SearchType = "invalid"
	// SearchTypeAddress means we found an address with the given ID.
	SearchTypeAddress SearchType = "address"
	// SearchTypeBlock means we found a block with the given ID.
	SearchTypeBlock SearchType = "block"
	// SearchTypeTransaction means we found a transaction with the given ID.
	SearchTypeTransaction SearchType = "transaction"
	// SearchTypeSiacoinElement means we found a contract with the given ID.
	SearchTypeSiacoinElement SearchType = "siacoinElement"
	// SearchTypeSiafundElement means we found a contract with the given ID.
	SearchTypeSiafundElement SearchType = "siafundElement"
	// SearchTypeContract means we found a contract with the given ID.
	SearchTypeContract SearchType = "contract"
)

// A SiacoinInput is a types.SiacoinInput with information about the parent
// value.
type SiacoinInput struct {
	Address types.Address  `json:"address"`
	Value   types.Currency `json:"value"`
	types.SiacoinInput
}

// A SiafundInput is a types.SiafundInput with information about the parent
// value.
type SiafundInput struct {
	Address types.Address `json:"address"`
	Value   uint64        `json:"value"`
	types.SiafundInput
}

// A SiacoinOutput is a types.SiacoinElement with added fields for the source
// and when it was spent.
type SiacoinOutput struct {
	Source     Source            `json:"source"`
	SpentIndex *types.ChainIndex `json:"spentIndex"`
	types.SiacoinElement
}

// A SiafundOutput is a types.SiafundElement with an added field for when it
// was spent.
type SiafundOutput struct {
	SpentIndex *types.ChainIndex `json:"spentIndex"`
	types.SiafundElement
}

// A FileContract is a types.FileContractElement with added fields for
// resolved/valid state.
type FileContract struct {
	Resolved bool `json:"resolved"`
	Valid    bool `json:"valid"`

	TransactionID types.TransactionID `json:"transactionID"`

	ConfirmationIndex         *types.ChainIndex    `json:"confirmationIndex"`
	ConfirmationTransactionID *types.TransactionID `json:"confirmationTransactionID"`

	ProofIndex         *types.ChainIndex    `json:"proofIndex"`
	ProofTransactionID *types.TransactionID `json:"proofTransactionID"`

	types.FileContractElement
}

// A FileContractRevision is a FileContract with extra fields for revision
// information.
type FileContractRevision struct {
	ParentID         types.FileContractID   `json:"parentID"`
	UnlockConditions types.UnlockConditions `json:"unlockConditions"`

	FileContract
}

// A Transaction is a transaction that uses the wrapped types above.
type Transaction struct {
	ID                    types.TransactionID          `json:"id"`
	SiacoinInputs         []SiacoinInput               `json:"siacoinInputs,omitempty"`
	SiacoinOutputs        []SiacoinOutput              `json:"siacoinOutputs,omitempty"`
	SiafundInputs         []SiafundInput               `json:"siafundInputs,omitempty"`
	SiafundOutputs        []SiafundOutput              `json:"siafundOutputs,omitempty"`
	FileContracts         []FileContract               `json:"fileContracts,omitempty"`
	FileContractRevisions []FileContractRevision       `json:"fileContractRevisions,omitempty"`
	StorageProofs         []types.StorageProof         `json:"storageProofs,omitempty"`
	MinerFees             []types.Currency             `json:"minerFees,omitempty"`
	ArbitraryData         [][]byte                     `json:"arbitraryData,omitempty"`
	Signatures            []types.TransactionSignature `json:"signatures,omitempty"`

	HostAnnouncements []chain.HostAnnouncement `json:"hostAnnouncements,omitempty"`
}

// A V2Transaction is a v2 transaction that uses the wrapped types above.
type V2Transaction struct {
	ID            types.TransactionID `json:"id"`
	ArbitraryData []byte              `json:"arbitraryData,omitempty"`

	HostAnnouncements []chain.HostAnnouncement `json:"hostAnnouncements,omitempty"`
}

// V2BlockData is a struct containing the fields from types.V2BlockData and our
// modified explorer.V2Transaction type.
type V2BlockData struct {
	Height       uint64          `json:"height"`
	Commitment   types.Hash256   `json:"commitment"`
	Transactions []V2Transaction `json:"transactions"`
}

// A Block is a block containing wrapped transactions and siacoin
// outputs for the miner payouts.
type Block struct {
	Height       uint64          `json:"height"`
	ParentID     types.BlockID   `json:"parentID"`
	Nonce        uint64          `json:"nonce"`
	Timestamp    time.Time       `json:"timestamp"`
	MinerPayouts []SiacoinOutput `json:"minerPayouts"`
	Transactions []Transaction   `json:"transactions"`

	V2 *V2BlockData `json:"v2,omitempty"`
}

// Metrics contains various statistics relevant to the health of the Sia network.
type Metrics struct {
	// Current chain index
	Index types.ChainIndex `json:"index"`
	// Current difficulty
	Difficulty consensus.Work `json:"difficulty"`
	// Siafund pool value
	SiafundPool types.Currency `json:"siafundPool"`
	// Total announced hosts
	TotalHosts uint64 `json:"totalHosts"`
	// Number of active contracts
	ActiveContracts uint64 `json:"activeContracts"`
	// Number of failed contracts
	FailedContracts uint64 `json:"failedContracts"`
	// Number of successful contracts
	SuccessfulContracts uint64 `json:"successfulContracts"`
	// Current storage utilization, in bytes
	StorageUtilization uint64 `json:"storageUtilization"`
	// Current circulating supply
	CirculatingSupply types.Currency `json:"circulatingSupply"`
	// Total contract revenue
	ContractRevenue types.Currency `json:"contractRevenue"`
}

// HostScan represents the results of a host scan.
type HostScan struct {
	PublicKey   types.PublicKey `json:"publicKey"`
	CountryCode string          `json:"countryCode"`
	Success     bool            `json:"success"`
	Timestamp   time.Time       `json:"timestamp"`

	Settings   rhpv2.HostSettings   `json:"settings"`
	PriceTable rhpv3.HostPriceTable `json:"priceTable"`
}

// Host represents a host and the information gathered from scanning it.
type Host struct {
	PublicKey   types.PublicKey `json:"publicKey"`
	NetAddress  string          `json:"netAddress"`
	CountryCode string          `json:"countryCode"`

	KnownSince             time.Time `json:"knownSince"`
	LastScan               time.Time `json:"lastScan"`
	LastScanSuccessful     bool      `json:"lastScanSuccessful"`
	LastAnnouncement       time.Time `json:"lastAnnouncement"`
	TotalScans             uint64    `json:"totalScans"`
	SuccessfulInteractions uint64    `json:"successfulInteractions"`
	FailedInteractions     uint64    `json:"failedInteractions"`

	Settings   rhpv2.HostSettings   `json:"settings"`
	PriceTable rhpv3.HostPriceTable `json:"priceTable"`
}

// HostMetrics represents averages of scanned information from hosts.
type HostMetrics struct {
	ActiveHosts uint64               `json:"activeHosts"`
	Settings    rhpv2.HostSettings   `json:"settings"`
	PriceTable  rhpv3.HostPriceTable `json:"priceTable"`
}
