// Copyright (C) 2019-2024, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ledger2

import (
	"fmt"
	"math/big"

	"github.com/ava-labs/avalanchego/ids"
	"github.com/ava-labs/avalanchego/utils/crypto/keychain"
	"github.com/ava-labs/avalanchego/utils/hashing"
	"github.com/ava-labs/avalanchego/version"
	"github.com/ava-labs/subnet-evm/core/types"
	"github.com/ethereum/go-ethereum/rlp"

	//ledger "github.com/ava-labs/ledger-avalanche/go"
	bip32 "github.com/tyler-smith/go-bip32"
)

const (
	rootPath          = "m/44'/9000'/0'" // BIP44: m / purpose' / coin_type' / account'
	ledgerBufferLimit = 8192
	ledgerPathSize    = 9
)

type Ledger2 interface {
	keychain.Ledger //use base ledger interface from avalanchego
	// add c-chain functions to get other addresses
	SignEthTransaction(chainID *big.Int, unsignedTx *types.Transaction, ledgerIndex uint32) (*types.Transaction, error)
	EthAddress(addressIndex uint32) (ids.ShortID, error)
	PXAddress(addressIndex uint32) (ids.ShortID, error)
}

var _ keychain.Ledger = (*LedgerCustom)(nil)

// Ledger is a wrapper around the low-level Ledger Device interface that
// provides Avalanche-specific access.
type LedgerCustom struct {
	device *LedgerAvalanche
	epk    *bip32.Key
}

func New() (Ledger2, error) {
	device, err := FindLedgerAvalancheApp()
	return &LedgerCustom{
		device: device,
	}, err
}

// ledger live evm compatible hd path
func addressPathLedgerLiveBip44(index uint32) string {
	return fmt.Sprintf("m/44'/60'/%d'/0/0", index)
}

// avalanche p-chain hd path
func addressPath(index uint32) string {
	return fmt.Sprintf("%s/0/%d", rootPath, index)
}

func (l *LedgerCustom) Address(hrp string, addressIndex uint32) (ids.ShortID, error) {
	resp, err := l.device.GetPubKey(addressPath(addressIndex), true, hrp, "")
	if err != nil {
		return ids.ShortEmpty, err
	}
	return ids.ToShortID(resp.Hash)
}
func (l *LedgerCustom) PXAddress(addressIndex uint32) (ids.ShortID, error) {
	resp, err := l.device.GetPubKey(addressPath(addressIndex), false, "", "")
	if err != nil {
		return ids.ShortEmpty, err
	}
	return ids.ToShortID(resp.Hash)
}

func (l *LedgerCustom) EthAddress(addressIndex uint32) (ids.ShortID, error) {
	resp, err := l.device.GetEthPubKey(addressPathLedgerLiveBip44(addressIndex), false)
	if err != nil {
		return ids.ShortEmpty, err
	}
	return ids.ToShortID(resp.Hash)
}

func (l *LedgerCustom) Addresses(addressIndices []uint32) ([]ids.ShortID, error) {
	if l.epk == nil {
		pk, chainCode, err := l.device.GetExtPubKey(rootPath, false, "", "")
		if err != nil {
			return nil, err
		}
		l.epk = &bip32.Key{
			Key:       pk,
			ChainCode: chainCode,
		}
	}
	// derivation path rootPath/0 (BIP44 change level, when set to 0, known as external chain)
	externalChain, err := l.epk.NewChildKey(0)
	if err != nil {
		return nil, err
	}
	addresses := make([]ids.ShortID, len(addressIndices))
	for i, addressIndex := range addressIndices {
		// derivation path rootPath/0/v (BIP44 address index level)
		address, err := externalChain.NewChildKey(addressIndex)
		if err != nil {
			return nil, err
		}
		copy(addresses[i][:], hashing.PubkeyBytesToAddress(address.Key))
	}
	return addresses, nil
}

func convertToSigningPaths(input []uint32) []string {
	output := make([]string, len(input))
	for i, v := range input {
		output[i] = fmt.Sprintf("0/%d", v)
	}
	return output
}

func (l *LedgerCustom) SignHash(hash []byte, addressIndices []uint32) ([][]byte, error) {
	strIndices := convertToSigningPaths(addressIndices)
	response, err := l.device.SignHash(rootPath, strIndices, hash)
	if err != nil {
		return nil, fmt.Errorf("%w: unable to sign hash", err)
	}
	responses := make([][]byte, len(addressIndices))
	for i, index := range strIndices {
		sig, ok := response.Signature[index]
		if !ok {
			return nil, fmt.Errorf("missing signature %s", index)
		}
		responses[i] = sig
	}
	return responses, nil
}

func (l *LedgerCustom) Sign(txBytes []byte, addressIndices []uint32) ([][]byte, error) {
	// will pass to the ledger addressIndices both as signing paths and change paths
	numSigningPaths := len(addressIndices)
	numChangePaths := len(addressIndices)
	if len(txBytes)+(numSigningPaths+numChangePaths)*ledgerPathSize > ledgerBufferLimit {
		// There is a limit on the tx length that can be parsed by the ledger
		// app. When the tx that is being signed is too large, we sign with hash
		// instead.
		//
		// Ref: https://github.com/ava-labs/avalanche-wallet-sdk/blob/9a71f05e424e06b94eaccf21fd32d7983ed1b040/src/Wallet/Ledger/provider/ZondaxProvider.ts#L68
		unsignedHash := hashing.ComputeHash256(txBytes)
		return l.SignHash(unsignedHash, addressIndices)
	}
	strIndices := convertToSigningPaths(addressIndices)
	response, err := l.device.Sign(rootPath, strIndices, txBytes, strIndices)
	if err != nil {
		return nil, fmt.Errorf("%w: unable to sign transaction", err)
	}
	responses := make([][]byte, len(strIndices))
	for i, index := range strIndices {
		sig, ok := response.Signature[index]
		if !ok {
			return nil, fmt.Errorf("missing signature %s", index)
		}
		responses[i] = sig
	}
	return responses, nil
}

func (l *LedgerCustom) SignEthTransaction(chainID *big.Int, unsignedTx *types.Transaction, ledgerIndex uint32) (*types.Transaction, error) {
	txSigner := types.LatestSignerForChainID(chainID)
	txBytes, err := unsignedTx.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal transaction: %w", err)
	}
	prefix := []byte{}
	suffix := []interface{}{}
	if txBytes[0] == 0x01 || txBytes[0] == 0x02 {
		prefix = txBytes[:1]
		txBytes = txBytes[1:]
	} else { // legacy
		// For legacy transactions, append chainId, empty r, empty s
		if chainID != nil {
			suffix = []interface{}{uint(chainID.Uint64()), uint(0), uint(0)}
		}
	}
	// Decode the transaction body (without the original signature)
	var decoded interface{}
	if err := rlp.DecodeBytes(txBytes, &decoded); err != nil {
		return nil, fmt.Errorf("failed to decode transaction: %w", err)
	}
	// Convert decoded to list and remove signature fields (last 3 elements)
	decodedList, ok := decoded.([]interface{})
	if !ok {
		return nil, fmt.Errorf("decoded transaction is not a list")
	}
	// Remove V, R, S signature components
	unsigned := decodedList[:len(decodedList)-3]
	// Add suffix elements if present
	if len(suffix) > 0 {
		unsigned = append(unsigned, suffix...)
	}
	// Encode the unsigned transaction
	encoded, err := rlp.EncodeToBytes(unsigned)
	if err != nil {
		return nil, fmt.Errorf("failed to encode unsigned transaction: %w", err)
	}
	tx := append(prefix, encoded...)

	signatureVRS, err := l.SignEthPayload(tx, ledgerIndex)
	if err != nil {
		fmt.Println("Error signing transaction using ledger")
		return nil, err
	}
	v := signatureVRS[0]
	r := signatureVRS[1:33]
	s := signatureVRS[33:65]
	signature := append(r, s...)
	signature = append(signature, byte(v))
	signedTx, err := unsignedTx.WithSignature(txSigner, signature)
	if err != nil {

		return nil, fmt.Errorf("Error adding signature to unsigned transaction: %w", err)
	}
	return signedTx, nil
}

func (l *LedgerCustom) SignEthPayload(rlpEncodedTx []byte, addressIndex uint32) ([]byte, error) {
	hdPath := addressPathLedgerLiveBip44(addressIndex)
	response, err := l.device.SignEthTransaction(hdPath, rlpEncodedTx)
	// response, err := l.device.SignEth(hdPath, rlpEncodedTx)
	if err != nil {
		return nil, fmt.Errorf("%w: unable to sign hash", err)
	}
	sig, ok := response.Signature[hdPath]
	if !ok {
		return nil, fmt.Errorf("missing signature %s", hdPath)
	}
	return sig, nil
}

func (l *LedgerCustom) Version() (*version.Semantic, error) {
	resp, err := l.device.GetVersion()
	if err != nil {
		return nil, err
	}
	return &version.Semantic{
		Major: int(resp.Major),
		Minor: int(resp.Minor),
		Patch: int(resp.Patch),
	}, nil
}

func (l *LedgerCustom) Disconnect() error {
	return l.device.Close()
}
