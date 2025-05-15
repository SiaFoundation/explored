package explorer

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"go.sia.tech/core/consensus"
	rhpv2 "go.sia.tech/core/rhp/v2"
	rhpv3 "go.sia.tech/core/rhp/v3"
	rhpv4 "go.sia.tech/core/rhp/v4"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/chain"
	"go.sia.tech/coreutils/rhp/v4/siamux"
	"go.sia.tech/explored/geoip"
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
	// SearchTypeV2Transaction means we found a v2 transaction with the given ID.
	SearchTypeV2Transaction SearchType = "v2Transaction"
	// SearchTypeSiacoinElement means we found a siacoin element with the given
	// ID.
	SearchTypeSiacoinElement SearchType = "siacoinElement"
	// SearchTypeSiafundElement means we found a siafund element with the given
	// ID.
	SearchTypeSiafundElement SearchType = "siafundElement"
	// SearchTypeContract means we found a contract with the given ID.
	SearchTypeContract SearchType = "contract"
	// SearchTypeV2Contract means we found a V2 contract with the given ID.
	SearchTypeV2Contract SearchType = "v2Contract"
	// SearchTypeHost means we found a host with the given pubkey.
	SearchTypeHost SearchType = "host"
)

// A V2Resolution represents the type of a v2 file contract resolution.
type V2Resolution int

const (
	// V2ResolutionInvalid represents an invalid resolution type.
	V2ResolutionInvalid V2Resolution = iota
	// V2ResolutionRenewal represents a renewal.
	V2ResolutionRenewal
	// V2ResolutionStorageProof represents a storage proof.
	V2ResolutionStorageProof
	// V2ResolutionExpiration represents contract expiry without renewal or a
	// storage proof being submitted.
	V2ResolutionExpiration
)

// MarshalJSON implements json.Marshaler.
func (s V2Resolution) MarshalJSON() ([]byte, error) {
	sourceToV2Resolution := map[V2Resolution]string{
		V2ResolutionInvalid:      "invalid",
		V2ResolutionRenewal:      "renewal",
		V2ResolutionStorageProof: "storage_proof",
		V2ResolutionExpiration:   "expiration",
	}

	str, ok := sourceToV2Resolution[s]
	if !ok {
		str = "invalid" // "invalid" if source is unknown
	}
	return json.Marshal(str)
}

// UnmarshalJSON implements json.Unmarshaler.
func (s *V2Resolution) UnmarshalJSON(data []byte) error {
	stringToV2Resolution := map[string]V2Resolution{
		"invalid":       V2ResolutionInvalid,
		"renewal":       V2ResolutionRenewal,
		"storage_proof": V2ResolutionStorageProof,
		"expiration":    V2ResolutionExpiration,
	}

	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}

	source, ok := stringToV2Resolution[str]
	if !ok {
		return errors.New("invalid resolution type")
	}

	*s = source
	return nil
}

// V2ResolutionType determines the V2Resolution enum value from a v2 file
// contract resolution.
func V2ResolutionType(res types.V2FileContractResolutionType) (result V2Resolution) {
	switch res.(type) {
	case *types.V2FileContractRenewal:
		result = V2ResolutionRenewal
	case *types.V2StorageProof:
		result = V2ResolutionStorageProof
	case *types.V2FileContractExpiration:
		result = V2ResolutionExpiration
	default:
		panic("unknown resolution type")
	}
	return
}

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

// A ContractSiacoinOutput is a SiacoinOutput with an added field for its ID.
type ContractSiacoinOutput struct {
	ID types.SiacoinOutputID `json:"id"`
	types.SiacoinOutput
}

// A ExtendedFileContract is a FileContract with added fields for
// resolved/valid state, and when the transaction was confirmed and proved.
type ExtendedFileContract struct {
	Resolved bool `json:"resolved"`
	Valid    bool `json:"valid"`

	TransactionID types.TransactionID `json:"transactionID"`

	ConfirmationIndex         types.ChainIndex    `json:"confirmationIndex"`
	ConfirmationTransactionID types.TransactionID `json:"confirmationTransactionID"`

	ProofIndex         *types.ChainIndex    `json:"proofIndex"`
	ProofTransactionID *types.TransactionID `json:"proofTransactionID"`

	ID                 types.FileContractID    `json:"id"`
	Filesize           uint64                  `json:"filesize"`
	FileMerkleRoot     types.Hash256           `json:"fileMerkleRoot"`
	WindowStart        uint64                  `json:"windowStart"`
	WindowEnd          uint64                  `json:"windowEnd"`
	Payout             types.Currency          `json:"payout"`
	ValidProofOutputs  []ContractSiacoinOutput `json:"validProofOutputs"`
	MissedProofOutputs []ContractSiacoinOutput `json:"missedProofOutputs"`
	UnlockHash         types.Address           `json:"unlockHash"`
	RevisionNumber     uint64                  `json:"revisionNumber"`
}

// A FileContractRevision is a FileContract with extra fields for revision
// information.
type FileContractRevision struct {
	ParentID         types.FileContractID   `json:"parentID"`
	UnlockConditions types.UnlockConditions `json:"unlockConditions"`

	ExtendedFileContract
}

// A Transaction is a transaction that uses the wrapped types above.
type Transaction struct {
	ID types.TransactionID `json:"id"`

	SiacoinInputs         []SiacoinInput               `json:"siacoinInputs,omitempty"`
	SiacoinOutputs        []SiacoinOutput              `json:"siacoinOutputs,omitempty"`
	SiafundInputs         []SiafundInput               `json:"siafundInputs,omitempty"`
	SiafundOutputs        []SiafundOutput              `json:"siafundOutputs,omitempty"`
	FileContracts         []ExtendedFileContract       `json:"fileContracts,omitempty"`
	FileContractRevisions []FileContractRevision       `json:"fileContractRevisions,omitempty"`
	StorageProofs         []types.StorageProof         `json:"storageProofs,omitempty"`
	MinerFees             []types.Currency             `json:"minerFees,omitempty"`
	ArbitraryData         [][]byte                     `json:"arbitraryData,omitempty"`
	Signatures            []types.TransactionSignature `json:"signatures,omitempty"`

	HostAnnouncements []chain.HostAnnouncement `json:"hostAnnouncements,omitempty"`
}

// A V2FileContract is a v2 file contract.
type V2FileContract struct {
	TransactionID types.TransactionID `json:"transactionID"`

	RenewedFrom *types.FileContractID `json:"renewedFrom"`
	RenewedTo   *types.FileContractID `json:"renewedTo"`

	ConfirmationIndex         types.ChainIndex    `json:"confirmationIndex"`
	ConfirmationTransactionID types.TransactionID `json:"confirmationTransactionID"`

	ResolutionType          *V2Resolution        `json:"resolutionType"`
	ResolutionIndex         *types.ChainIndex    `json:"resolutionIndex"`
	ResolutionTransactionID *types.TransactionID `json:"resolutionTransactionID"`

	types.V2FileContractElement
}

// A V2FileContractRevision is a V2 file contract revision with the
// explorer V2FileContract type.
type V2FileContractRevision struct {
	Parent   V2FileContract `json:"parent"`
	Revision V2FileContract `json:"revision"`
}

// A V2HostAnnouncement is a types.V2HostAnnouncement list of net addresses
// with the host public key attached.
type V2HostAnnouncement struct {
	PublicKey types.PublicKey `json:"publicKey"`
	chain.V2HostAnnouncement
}

// A V2FileContractRenewal renews a file contract.
type V2FileContractRenewal struct {
	FinalRenterOutput types.SiacoinOutput `json:"finalRenterOutput"`
	FinalHostOutput   types.SiacoinOutput `json:"finalHostOutput"`
	RenterRollover    types.Currency      `json:"renterRollover"`
	HostRollover      types.Currency      `json:"hostRollover"`
	NewContract       V2FileContract      `json:"newContract"`

	// signatures cover above fields
	RenterSignature types.Signature `json:"renterSignature"`
	HostSignature   types.Signature `json:"hostSignature"`
}

// A V2FileContractResolution closes a v2 file contract's payment channel.
// There are four resolution types: renewwal, storage proof, finalization,
// and expiration.
type V2FileContractResolution struct {
	Parent     V2FileContract `json:"parent"`
	Type       V2Resolution   `json:"type"`
	Resolution any            `json:"resolution"`
}

// A V2Transaction is a V2 transaction that uses the wrapped types above.
type V2Transaction struct {
	ID types.TransactionID `json:"id"`

	SiacoinInputs  []types.V2SiacoinInput `json:"siacoinInputs,omitempty"`
	SiacoinOutputs []SiacoinOutput        `json:"siacoinOutputs,omitempty"`
	SiafundInputs  []types.V2SiafundInput `json:"siafundInputs,omitempty"`
	SiafundOutputs []SiafundOutput        `json:"siafundOutputs,omitempty"`

	FileContracts           []V2FileContract           `json:"fileContracts,omitempty"`
	FileContractRevisions   []V2FileContractRevision   `json:"fileContractRevisions,omitempty"`
	FileContractResolutions []V2FileContractResolution `json:"fileContractResolutions,omitempty"`

	Attestations  []types.Attestation `json:"attestations,omitempty"`
	ArbitraryData []byte              `json:"arbitraryData,omitempty"`

	NewFoundationAddress *types.Address `json:"newFoundationAddress,omitempty"`
	MinerFee             types.Currency `json:"minerFee"`

	HostAnnouncements []V2HostAnnouncement `json:"hostAnnouncements,omitempty"`
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
	LeafIndex    uint64          `json:"leafIndex"`
	MinerPayouts []SiacoinOutput `json:"minerPayouts"`
	Transactions []Transaction   `json:"transactions"`

	V2 *V2BlockData `json:"v2,omitempty"`
}

// V2Transactions returns the block's v2 transactions, if present.
func (b *Block) V2Transactions() []V2Transaction {
	if b.V2 != nil {
		return b.V2.Transactions
	}
	return nil
}

// Metrics contains various statistics relevant to the health of the Sia network.
type Metrics struct {
	// Current chain index
	Index types.ChainIndex `json:"index"`
	// Current difficulty
	Difficulty consensus.Work `json:"difficulty"`
	// Siafund pool value
	SiafundTaxRevenue types.Currency `json:"siafundTaxRevenue"`
	// Total announced hosts
	TotalHosts uint64 `json:"totalHosts"`
	// Number of leaves in the accumulator
	NumLeaves uint64 `json:"numLeaves"`
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
	PublicKey types.PublicKey `json:"publicKey"`
	Location  geoip.Location  `json:"location"`
	Success   bool            `json:"success"`
	Error     *string         `json:"error"`
	Timestamp time.Time       `json:"timestamp"`
	NextScan  time.Time       `json:"nextScan"`

	Settings   rhpv2.HostSettings   `json:"settings"`
	PriceTable rhpv3.HostPriceTable `json:"priceTable"`

	V2Settings rhpv4.HostSettings `json:"v2Settings"`
}

// UnscannedHost represents the metadata needed to scan a host.
type UnscannedHost struct {
	PublicKey                types.PublicKey    `json:"publicKey"`
	V2                       bool               `json:"v2"`
	NetAddress               string             `json:"netAddress"`
	V2NetAddresses           []chain.NetAddress `json:"v2NetAddresses,omitempty"`
	FailedInteractionsStreak uint64             `json:"failedInteractionsStreak"`
}

// V2SiamuxAddr returns the `Address` of the first TCP siamux `NetAddress` it
// finds in the host's list of net addresses.  The protocol for this address is
// ProtocolTCPSiaMux.
func (h UnscannedHost) V2SiamuxAddr() (string, bool) {
	for _, netAddr := range h.V2NetAddresses {
		if netAddr.Protocol == siamux.Protocol {
			return netAddr.Address, true
		}
	}
	return "", false
}

// IsV2 returns whether a host supports V2 or not.
func (h UnscannedHost) IsV2() bool {
	return len(h.V2NetAddresses) > 0
}

// Host represents a host and the information gathered from scanning it.
type Host struct {
	PublicKey      types.PublicKey    `json:"publicKey"`
	V2             bool               `json:"v2"`
	NetAddress     string             `json:"netAddress"`
	V2NetAddresses []chain.NetAddress `json:"v2NetAddresses,omitempty"`

	Location geoip.Location `json:"location"`

	KnownSince             time.Time `json:"knownSince"`
	LastScan               time.Time `json:"lastScan"`
	LastScanSuccessful     bool      `json:"lastScanSuccessful"`
	LastScanError          *string   `json:"lastScanError"`
	LastAnnouncement       time.Time `json:"lastAnnouncement"`
	NextScan               time.Time `json:"nextScan"`
	TotalScans             uint64    `json:"totalScans"`
	SuccessfulInteractions uint64    `json:"successfulInteractions"`
	FailedInteractions     uint64    `json:"failedInteractions"`

	Settings   rhpv2.HostSettings   `json:"settings"`
	PriceTable rhpv3.HostPriceTable `json:"priceTable"`

	V2Settings rhpv4.HostSettings `json:"v2Settings"`
}

// HostMetrics represents averages of scanned information from hosts.
type HostMetrics struct {
	// Number of hosts that were up as of there last scan
	ActiveHosts uint64 `json:"activeHosts"`
	// Total storage of all active hosts, in bytes
	TotalStorage uint64 `json:"totalStorage"`
	// Remaining storage of all active hosts, in bytes (storage utilization is
	// equal to TotalStorage - RemainingStorage)
	RemainingStorage uint64 `json:"remainingStorage"`

	Settings   rhpv2.HostSettings   `json:"settings"`
	PriceTable rhpv3.HostPriceTable `json:"priceTable"`
	V2Settings rhpv4.HostSettings   `json:"v2Settings"`
}

// HostSortDir represents the sorting direction for host filtering.
type HostSortDir string

const (
	// HostSortAsc means sorting in ascending order.
	HostSortAsc HostSortDir = "asc"
	// HostSortDesc means sorting in descending order.
	HostSortDesc HostSortDir = "desc"
)

// MarshalText implements encoding.TextMarshaler.
func (h HostSortDir) MarshalText() ([]byte, error) {
	switch h {
	case HostSortAsc, HostSortDesc:
		return []byte(h), nil
	default:
		return nil, fmt.Errorf("invalid HostSortDir: %s", h)
	}
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (h *HostSortDir) UnmarshalText(data []byte) error {
	switch string(data) {
	case string(HostSortAsc):
		*h = HostSortAsc
	case string(HostSortDesc):
		*h = HostSortDesc
	default:
		return fmt.Errorf("invalid HostSortDir: %s", data)
	}
	return nil
}

// HostSortColumn represents the sorting column for host filtering.
type HostSortColumn string

const (
	// HostSortDateCreated sorts hosts in the order they were first announced.
	HostSortDateCreated HostSortColumn = "date_created"
	// HostSortNetAddress sorts hosts by their net address.
	HostSortNetAddress HostSortColumn = "net_address"
	// HostSortPublicKey sorts hosts by their public key
	HostSortPublicKey HostSortColumn = "public_key"
	// HostSortAcceptingContracts sorts hosts by whether they accept contracts.
	HostSortAcceptingContracts HostSortColumn = "accepting_contracts"
	// HostSortUptime sorts hosts by their uptime.
	HostSortUptime HostSortColumn = "uptime"
	// HostSortStoragePrice sorts hosts by their storage price.
	HostSortStoragePrice HostSortColumn = "storage_price"
	// HostSortContractPrice sorts hosts by their contract price.
	HostSortContractPrice HostSortColumn = "contract_price"
	// HostSortDownloadPrice sorts hosts by their download price.
	HostSortDownloadPrice HostSortColumn = "download_price"
	// HostSortUploadPrice sorts hosts by their upload price.
	HostSortUploadPrice HostSortColumn = "upload_price"
	// HostSortUsedStorage sorts hosts by their used storage.
	HostSortUsedStorage HostSortColumn = "used_storage"
	// HostSortTotalStorage sorts hosts by their total storage.
	HostSortTotalStorage HostSortColumn = "total_storage"
)

// MarshalText implements encoding.TextMarshaler.
func (h HostSortColumn) MarshalText() ([]byte, error) {
	switch h {
	case HostSortDateCreated, HostSortNetAddress, HostSortPublicKey, HostSortAcceptingContracts,
		HostSortUptime, HostSortStoragePrice, HostSortContractPrice, HostSortDownloadPrice,
		HostSortUploadPrice, HostSortUsedStorage, HostSortTotalStorage:
		return []byte(h), nil
	default:
		return nil, fmt.Errorf("invalid HostSortColumn: %s", h)
	}
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (h *HostSortColumn) UnmarshalText(data []byte) error {
	switch string(data) {
	case string(HostSortDateCreated):
		*h = HostSortDateCreated
	case string(HostSortNetAddress):
		*h = HostSortNetAddress
	case string(HostSortPublicKey):
		*h = HostSortPublicKey
	case string(HostSortAcceptingContracts):
		*h = HostSortAcceptingContracts
	case string(HostSortUptime):
		*h = HostSortUptime
	case string(HostSortStoragePrice):
		*h = HostSortStoragePrice
	case string(HostSortContractPrice):
		*h = HostSortContractPrice
	case string(HostSortDownloadPrice):
		*h = HostSortDownloadPrice
	case string(HostSortUploadPrice):
		*h = HostSortUploadPrice
	case string(HostSortUsedStorage):
		*h = HostSortUsedStorage
	case string(HostSortTotalStorage):
		*h = HostSortTotalStorage
	default:
		return fmt.Errorf("invalid HostSortColumn: %s", data)
	}
	return nil
}

// HostQuery defines the filter and sort parameters for querying hosts.
type HostQuery struct {
	V2                   *bool             `json:"v2,omitempty"`
	PublicKeys           []types.PublicKey `json:"publicKeys,omitempty"`
	NetAddresses         []string          `json:"netAddresses,omitempty"`
	MinUptime            *float64          `json:"minUptime,omitempty"`
	MinDuration          *uint64           `json:"minDuration,omitempty"`
	MaxStoragePrice      *types.Currency   `json:"maxStoragePrice,omitempty"`
	MaxContractPrice     *types.Currency   `json:"maxContractPrice,omitempty"`
	MaxUploadPrice       *types.Currency   `json:"maxUploadPrice,omitempty"`
	MaxDownloadPrice     *types.Currency   `json:"maxDownloadPrice,omitempty"`
	MaxBaseRPCPrice      *types.Currency   `json:"maxBaseRPCPrice,omitempty"`
	MaxSectorAccessPrice *types.Currency   `json:"maxSectorAccessPrice,omitempty"`
	AcceptContracts      *bool             `json:"acceptContracts,omitempty"`
	Online               *bool             `json:"online,omitempty"`
}

// MarshalJSON implements json.Marshaler.  The embedded types.SiacoinInput
// in our SiacoinInput has its own marshaler that will override default
// marshaling and result in fields we expect being missing.
func (e SiacoinInput) MarshalJSON() ([]byte, error) {
	type siacoinInputNoMarshal types.SiacoinInput
	return json.Marshal(struct {
		siacoinInputNoMarshal                // inlined fields from SiacoinInput
		Address               types.Address  `json:"address"`
		Value                 types.Currency `json:"value"`
	}{
		siacoinInputNoMarshal: siacoinInputNoMarshal(e.SiacoinInput),
		Address:               e.Address,
		Value:                 e.Value,
	})
}

// MarshalJSON implements json.Marshaler.  The embedded types.SiafundInput
// in our SiafundInput has its own marshaler that will override default
// marshaling and result in fields we expect being missing.
func (e SiafundInput) MarshalJSON() ([]byte, error) {
	type siafundInputNoMarshal types.SiafundInput
	return json.Marshal(struct {
		siafundInputNoMarshal
		Address types.Address `json:"address"`
		Value   uint64        `json:"value"`
	}{
		siafundInputNoMarshal: siafundInputNoMarshal(e.SiafundInput),
		Address:               e.Address,
		Value:                 e.Value,
	})
}
