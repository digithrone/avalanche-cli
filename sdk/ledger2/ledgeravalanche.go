/*******************************************************************************
*   (c) 2018 - 2023 Zondax AG
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
// ********************************************************************************/

package ledger2

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/ethereum/go-ethereum/common"
	ledger_go "github.com/zondax/ledger-go"
	"golang.org/x/crypto/sha3"
)

// FindLedgerAvalancheApp FindLedgerAvalancheUserApp finds a Avax user app running in a ledger device
func FindLedgerAvalancheApp() (_ *LedgerAvalanche, rerr error) {
	ledgerAdmin := ledger_go.NewLedgerAdmin()
	ledgerAPI, err := ledgerAdmin.Connect(0)
	if err != nil {
		return nil, err
	}

	defer func() {
		if rerr != nil {
			ledgerAPI.Close()
		}
	}()

	app := &LedgerAvalanche{ledgerAPI, VersionInfo{}}
	appVersion, err := app.GetVersion()
	if err != nil {
		if err.Error() == "[APDU_CODE_CLA_NOT_SUPPORTED] CLA not supported" {
			err = errors.New("are you sure the Avalanche app is open?")
		}
		return nil, err
	}

	if err := app.CheckVersion(*appVersion); err != nil {
		return nil, err
	}

	return app, err
}

// Close closes a connection with the Avalanche user app
func (ledger *LedgerAvalanche) Close() error {
	return ledger.api.Close()
}

// CheckVersion returns true if the App version is supported by this checkvers
func (ledger *LedgerAvalanche) CheckVersion(ver VersionInfo) error {
	version, err := ledger.GetVersion()
	if err != nil {
		return err
	}

	return CheckVersion(*version, ver)
}

// GetVersion returns the current version of the Avalanche user app
func (ledger *LedgerAvalanche) GetVersion() (*VersionInfo, error) {
	message := []byte{CLA, INS_GET_VERSION, 0, 0, 0}
	response, err := ledger.api.Exchange(message)

	if err != nil {
		return nil, err
	}

	if len(response) < 4 {
		return nil, errors.New("invalid response")
	}

	ledger.version = VersionInfo{
		AppMode: response[0],
		Major:   response[1],
		Minor:   response[2],
		Patch:   response[3],
	}

	return &ledger.version, nil
}

// ParseBIP32Path converts a BIP32 path string to a byte slice
func ParseBIP32Path(path string) ([]byte, error) {
	if len(path) == 0 {
		return []byte{}, nil
	}

	var result []byte
	elements := strings.Split(path, "/")
	for _, pathElement := range elements {
		element := strings.Split(pathElement, "'")
		if len(element) == 1 {
			value, err := strconv.Atoi(element[0])
			if err != nil {
				return nil, err
			}
			buf := make([]byte, 4)
			binary.BigEndian.PutUint32(buf, uint32(value))
			result = append(result, buf...)
		} else {
			value, err := strconv.Atoi(element[0])
			if err != nil {
				return nil, err
			}
			buf := make([]byte, 4)
			binary.BigEndian.PutUint32(buf, 0x80000000|uint32(value))
			result = append(result, buf...)
		}
	}
	return result, nil
}

// GetPubKey returns the pubkey and hash
func (ledger *LedgerAvalanche) GetEthPubKey(path string, show bool) (*ResponseAddr, error) {
	// serializedPath, err := SerializePath(path)
	// if err != nil {
	// 	return nil, err
	// }

	// serializedChainID, err := SerializeChainID(chainid)
	// if err != nil {
	// 	return nil, err
	// }

	p1 := byte(P1_ONLY_RETRIEVE)
	if show {
		p1 = byte(P1_SHOW_ADDRESS_IN_DEVICE)
	}

	bip32Bytes, err := SerializePath(path)
	if err != nil {
		return nil, err
	}

	numberOfBip32Derivations := byte(len(bip32Bytes))
	apdu := []byte{CLA_ETH, INS_GET_ADDR, p1, 0x00, numberOfBip32Derivations}
	// apdu = append(apdu, numberOfBip32Derivations)
	// apdu = append(apdu, byte(len(donglePath)/4))
	apdu = append(apdu, bip32Bytes...)

	response, err := ledger.api.Exchange(apdu)
	if err != nil {
		return nil, err
	}

	if len(response) < 1 {
		return nil, errors.New("invalid response")
	}

	// Parse the response
	publicKeyLen := response[0]
	if len(response) < int(publicKeyLen)+2 {
		return nil, errors.New("invalid response length")
	}

	publicKey := response[1 : publicKeyLen+1]
	pubkeyLen := len(publicKey)
	if pubkeyLen != 65 {
		return nil, errors.New("invalid pubkey length (expected 65 bytes)")
	}
	ethAddrLen := response[publicKeyLen+1]
	if len(response) < int(publicKeyLen)+int(ethAddrLen)+2 {
		return nil, errors.New("invalid response length")
	}

	address := string(response[publicKeyLen+2 : publicKeyLen+2+ethAddrLen])

	// // Check if chain code is present
	// var chainCode []byte
	// if len(response) > int(publicKeyLen)+int(ethAddrLen)+2 {
	// 	chainCode = response[publicKeyLen+2+ethAddrLen:]
	// }
	pubKeyWithoutPrefix := publicKey[1:]
	hash := sha3.NewLegacyKeccak256()
	hash.Write((pubKeyWithoutPrefix))
	hashed := hash.Sum(nil)[12:]

	return &ResponseAddr{PublicKey: publicKey, Address: address, Hash: hashed}, nil
}

// GetPubKey returns the pubkey and hash
func (ledger *LedgerAvalanche) GetPubKey(path string, show bool, hrp string, chainid string) (*ResponseAddr, error) {
	if len(hrp) > 83 {
		return nil, errors.New("hrp len should be < 83 chars")
	}

	serializedHRP, err := SerializeHrp(hrp)
	if err != nil {
		return nil, err
	}

	serializedPath, err := SerializePath(path)
	if err != nil {
		return nil, err
	}

	serializedChainID, err := SerializeChainID(chainid)
	if err != nil {
		return nil, err
	}

	p1 := byte(P1_ONLY_RETRIEVE)
	if show {
		p1 = byte(P1_SHOW_ADDRESS_IN_DEVICE)
	}

	// Prepare message
	header := []byte{CLA, INS_GET_ADDR, p1, 0, 0}
	message := append(header, serializedHRP...)
	message = append(message, serializedChainID...)
	message = append(message, serializedPath...)
	message[4] = byte(len(message) - len(header)) // update length

	response, err := ledger.api.Exchange(message)
	if err != nil {
		return nil, err
	}

	if len(response) < 35+len(hrp) {
		return nil, errors.New("Invalid response")
	}

	// [publicKeyLen | publicKey | hash | address | errorCode]
	publicKeyLen := response[0]
	publicKey := append([]byte{}, response[1:publicKeyLen+1]...)
	hash := append([]byte{}, response[publicKeyLen+1:publicKeyLen+1+20]...)
	address := string(response[publicKeyLen+1+20:])

	return &ResponseAddr{publicKey, hash, address}, nil
}

// GetExtPubKey returns the extended pubkey
func (ledger *LedgerAvalanche) GetExtPubKey(path string, show bool, hrp string, chainid string) ([]byte, []byte, error) {
	if len(hrp) > 83 {
		return nil, nil, errors.New("hrp len should be < 83 chars")
	}

	serializedHRP, err := SerializeHrp(hrp)
	if err != nil {
		return nil, nil, err
	}

	serializedPath, err := SerializePath(path)
	if err != nil {
		return nil, nil, err
	}

	serializedChainID, err := SerializeChainID(chainid)
	if err != nil {
		return nil, nil, err
	}

	p1 := byte(P1_ONLY_RETRIEVE)
	if show {
		p1 = byte(P1_SHOW_ADDRESS_IN_DEVICE)
	}

	// Prepare message
	header := []byte{CLA, INS_GET_EXTENDED_PUBLIC_KEY, p1, 0, 0}
	message := append(header, serializedHRP...)
	message = append(message, serializedChainID...)
	message = append(message, serializedPath...)
	message[4] = byte(len(message) - len(header)) // update length

	response, err := ledger.api.Exchange(message)
	if err != nil {
		return nil, nil, err
	}

	if len(response) < 32 {
		return nil, nil, errors.New("Invalid response")
	}

	publicKeyLen := response[0]
	publicKey := append([]byte{}, response[1:publicKeyLen+1]...)
	chainCode := append([]byte{}, response[publicKeyLen+1:]...)

	return publicKey, chainCode, nil
}

func (ledger *LedgerAvalanche) Sign(pathPrefix string, signingPaths []string, message []byte, changePaths []string) (*ResponseSign, error) {
	paths := signingPaths
	if changePaths != nil {
		paths = append(paths, changePaths...)
		paths = RemoveDuplicates(paths)
	}

	serializedPath, err := SerializePath(pathPrefix)
	if err != nil {
		return nil, err
	}

	payloadType := PAYLOAD_INIT
	p2 := FIRST_MESSAGE
	header := []byte{CLA, INS_SIGN, byte(payloadType), byte(p2), byte(len(serializedPath))}
	bytesToSend := append(header, serializedPath...)
	_, err = ledger.api.Exchange(bytesToSend)
	if err != nil {
		return nil, errors.New("command rejected")
	}

	msg := ConcatMessageAndChangePath(message, paths)

	for i := 0; i < len(msg); i += CHUNK_SIZE {
		end := i + CHUNK_SIZE
		payloadType := PAYLOAD_ADD
		p2 := 0

		if end > len(msg) {
			end = len(msg)
			payloadType = PAYLOAD_LAST
		}
		chunk := msg[i:end]
		chunkSize := end - i

		header := []byte{CLA, INS_SIGN, byte(payloadType), byte(p2), byte(chunkSize)}
		bytesToSend := append(header, chunk...)
		response, err := ledger.api.Exchange(bytesToSend)
		if err != nil {
			if err.Error() == "[APDU_CODE_BAD_KEY_HANDLE] The parameters in the data field are incorrect" {
				// In this special case, we can extract additional info
				return nil, fmt.Errorf("%w extra_info=(%s)", err, string(response))
			}
			if err.Error() == "[APDU_CODE_DATA_INVALID] Referenced data reversibly blocked (invalidated)" {
				return nil, fmt.Errorf("%w extra_info=(%s)", err, string(response))
			}
			return nil, err
		}
	}

	// Transaction was approved so start iterating over signing_paths to sign
	// and collect each signature
	return SignAndCollect(signingPaths, ledger)
}

func parseBIP32Path(path string) ([]byte, error) {
	if len(path) == 0 {
		return []byte{}, nil
	}

	var result bytes.Buffer
	elements := strings.Split(path, "/")
	for _, pathElement := range elements[1:] {
		element := strings.Split(pathElement, "'")
		if len(element) == 1 {
			value, err := strconv.Atoi(element[0])
			if err != nil {
				return nil, err
			}
			buf := make([]byte, 4)
			binary.BigEndian.PutUint32(buf, uint32(value))
			result.Write(buf)
		} else {
			value, err := strconv.Atoi(element[0])
			if err != nil {
				return nil, err
			}
			buf := make([]byte, 4)
			binary.BigEndian.PutUint32(buf, 0x80000000|uint32(value))
			result.Write(buf)
		}
	}
	return result.Bytes(), nil
}
func (ledger *LedgerAvalanche) SignEthTransaction(bip32Path string, rlpEncodedTexWithoutVRS []byte) (*ResponseSign, error) {
	hdPathPayload, err := parseBIP32Path(bip32Path)
	if err != nil {
		return nil, err
	}
	// rlpEncodedTexWithoutVRSLen := len(rlpEncodedTexWithoutVRS)
	hdPathPayloadLen := len(hdPathPayload)
	var apdus [][]byte
	payload := []byte{byte(hdPathPayloadLen / 4)} // length of hdPath segments
	payload = append(payload, hdPathPayload...)
	payload = append(payload, rlpEncodedTexWithoutVRS...)
	fmt.Println("HD:", common.Bytes2Hex(hdPathPayload))
	fmt.Println("Rlp:", common.Bytes2Hex(rlpEncodedTexWithoutVRS))
	p1 := 0x0 //P1TypeSignFirstChunk
	for len(payload) > 0 {
		chunkSize := 255
		if len(payload) < chunkSize {
			chunkSize = len(payload)
		}
		chunk := payload[:chunkSize]
		apdu := []byte{CLA_ETH, INS_SIGN_HASH, byte(p1), 0x00, byte(chunkSize)}
		apdu = append(apdu, chunk...)
		apdus = append(apdus, apdu)
		fmt.Println("Chunk len:", chunkSize)
		fmt.Println("Chunk data:", common.Bytes2Hex(chunk))
		payload = payload[chunkSize:]
		p1 = 0x80 //P1TypeSignSubsequentChunk
	}
	//loop through all the apdus except the last one
	for _, apdu := range apdus[:len(apdus)-1] {
		if res, err := ledger.api.Exchange(apdu); err != nil {
			if len(res) != 0 {
				return nil, errors.New("wrong response. Non final chunk should return empty response: " + err.Error())
			}
			return nil, err
		}
	}
	signature, err := ledger.api.Exchange(apdus[len(apdus)-1])
	if err != nil {
		return nil, err
	}
	return &ResponseSign{rlpEncodedTexWithoutVRS, map[string][]byte{bip32Path: signature}}, nil
}
func (ledger *LedgerAvalanche) SignEth(bip32Path string, rlpEncodedTx []byte) (*ResponseSign, error) {
	hdPathPayload, err := parseBIP32Path(bip32Path)
	if err != nil {
		return nil, err
	}

	// payload = append(payload, rlpEncodedTx...)
	p1 := 0x0 //P1TypeSignFirstC80hunk
	apdu := []byte{CLA_ETH, INS_SIGN_HASH, byte(p1), 0x00}
	hdPathLength := len(hdPathPayload)
	rlpLen := len(rlpEncodedTx)
	apdu = append(apdu, byte(hdPathLength+1+rlpLen))
	apdu = append(apdu, byte(hdPathLength/4))
	apdu = append(apdu, hdPathPayload...)
	apdu = append(apdu, rlpEncodedTx...)
	signature, err := ledger.api.Exchange(apdu)
	if err != nil {
		return nil, err
	}
	return &ResponseSign{rlpEncodedTx, map[string][]byte{bip32Path: signature}}, nil
	//
	// apdus := make([][]byte, 0)
	// for len(payload) > 0 {
	// 	chunkSize := 0xff
	// 	if len(payload) < chunkSize {
	// 		chunkSize = len(payload)
	// 	}
	// 	//apdu := ledger.Excha(InsTypeSign, p1, p2, payload[:chunkSize])
	// 	input := []byte{CLA_ETH, INS_SIGN_HASH, byte(p1), 0x00,  byte(chunkSize+1+)}
	// 	input = append(input,))
	// 	res, err := ledger.api.Exchange(input)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	apdus = append(apdus, res)
	// 	payload = payload[chunkSize:]
	// 	p1 = 0x80 //P1TypeSignSubsequentChunk
	// }

	// for _, apdu := range apdus[:len(apdus)-1] {
	// 	if res, err := ledger.api.Exchange(apdu); err != nil {
	// 		if len(res) != 0 {
	// 			return nil, errors.New("wrong response. Non final chunk should return empty response")
	// 		}
	// 		return nil, err
	// 	}
	// }
	// signature, err := ledger.api.Exchange(apdus[len(apdus)-1])
	// if err != nil {
	// 	return nil, err
	// }
	// return &ResponseSign{rlpEncodedTx, map[string][]byte{bip32Path: signature}}, nil
}

func (ledger *LedgerAvalanche) SignHash(pathPrefix string, signingPaths []string, hash []byte) (*ResponseSign, error) {
	if len(hash) != HASH_LEN {
		return nil, errors.New("wrong hash size")
	}

	serializedPath, err := SerializePath(pathPrefix)
	if err != nil {
		return nil, err
	}

	header := []byte{CLA, INS_SIGN_HASH, FIRST_MESSAGE, byte(0x00), byte(len(serializedPath) + len(hash))}
	bytesToSend := append(header, serializedPath...)
	bytesToSend = append(bytesToSend, hash...)
	firstResponse, err := ledger.api.Exchange(bytesToSend)

	if err != nil {
		return nil, errors.New("command rejected")
	}
	if len(firstResponse) != 0 {
		return nil, errors.New("wrong response")
	}

	return SignAndCollect(signingPaths, ledger)
}

func SignAndCollect(signingPaths []string, ledger *LedgerAvalanche) (*ResponseSign, error) {
	// Where each pair path_suffix, signature are stored
	signatures := make(map[string][]byte)

	for idx, suffix := range signingPaths {
		pathBuf, err := SerializePathSuffix(suffix)
		if err != nil {
			return nil, err
		}

		p1 := LAST_MESSAGE
		if idx < len(signingPaths)-1 {
			p1 = NEXT_MESSAGE
		}

		// Send path to sign hash that should be in device's ram memory
		header := []byte{CLA, INS_SIGN_HASH, byte(p1), byte(0x00), byte(len(pathBuf))}
		bytesToSend := append(header, pathBuf...)
		response, err := ledger.api.Exchange(bytesToSend)

		if err != nil {
			return nil, err
		}
		signatures[suffix] = response
	}

	return &ResponseSign{nil, signatures}, nil
}

func (ledger *LedgerAvalanche) VerifyMultipleSignatures(response ResponseSign, messageHash []byte, rootPath string, signingPaths []string, hrp string, chainID string) error {
	if len(response.Signature) != len(signingPaths) {
		return errors.New("sizes of signatures and paths don't match")
	}

	for _, suffix := range signingPaths {
		path := fmt.Sprintf("%s/%s", rootPath, suffix)

		addr, err := ledger.GetPubKey(path, false, hrp, chainID)
		if err != nil {
			return errors.New("error getting the pubkey")
		}

		hexString := fmt.Sprintf("%x", addr.PublicKey)
		fmt.Println(hexString)

		sigLen := len(response.Signature[suffix])
		verified := VerifySignature(addr.PublicKey, messageHash, response.Signature[suffix][:sigLen-1])

		if !verified {
			return errors.New("[VerifySig] Error verifying signature: ")
		}
	}
	return nil
}

// VerifySignature checks that the given public key created signature over hash.
// The public key should be in compressed (33 bytes) or uncompressed (65 bytes) format.
// The signature should have the 64 byte [R || S] format.
func VerifySignature(pubkey, hash, signature []byte) bool {
	if len(signature) != 64 {
		return false
	}
	var r, s btcec.ModNScalar
	if r.SetByteSlice(signature[:32]) {
		return false // overflow
	}
	if s.SetByteSlice(signature[32:]) {
		return false
	}
	sig := ecdsa.NewSignature(&r, &s)
	key, err := btcec.ParsePubKey(pubkey)
	if err != nil {
		return false
	}
	// Reject malleable signatures. libsecp256k1 does this check but btcec doesn't.
	if s.IsOverHalfOrder() {
		return false
	}
	return sig.Verify(hash, key)
}
