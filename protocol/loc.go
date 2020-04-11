package protocol

import (
	"crypto/rsa"
	"fmt"

	ss "github.com/superarius/shamir"

	"github.com/vmihailenco/msgpack"

	"github.com/ymarcus93/gallisto/encoding"
	"github.com/ymarcus93/gallisto/encryption"
	"github.com/ymarcus93/gallisto/shamir"
	"github.com/ymarcus93/gallisto/types"
)

func decryptDLOCCiphertextsAndValidate(dlocCiphertexts [][]byte, dlocPrivateKey *rsa.PrivateKey) ([]types.LOCData, error) {
	// Decrypt dloc ciphertexts
	dlocData, err := decryptLOCCiphertexts(dlocCiphertexts, dlocPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt DLOC ciphertexts: %v", err)
	}

	// Validate
	if !validateLOCData(dlocData, types.Director) {
		return nil, fmt.Errorf("decrypted DLOC ciphertexts but found non-Director data")
	}

	return dlocData, nil
}

// DecryptAssignmentData decrypts a list of encrypted assignment data. It does
// this by finding a common k value amongst matched dlocData and attempting to
// decrypt encrypted assignment keys with this k. It then uses the decrypted
// assignment keys to decrypt all assignment data.
func DecryptAssignmentData(dlocCiphertextsToFindKFrom [][]byte, dlocCiphertexts [][]byte, encryptedAssignmentData []encryption.GCMCiphertext, dlocPrivateKey *rsa.PrivateKey) ([]types.AssignmentData, error) {
	if len(dlocCiphertexts) != len(encryptedAssignmentData) {
		return nil, fmt.Errorf("mismatch length between dlocCiphertexts and encrypted assignment data")
	}

	dlocDataToDecrypt, err := decryptDLOCCiphertextsAndValidate(dlocCiphertexts, dlocPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt dlocCiphertexts: %v", err)
	}

	dlocDataToFindKFrom, err := decryptDLOCCiphertextsAndValidate(dlocCiphertextsToFindKFrom, dlocPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt dlocCiphertextsToFindKFrom: %v", err)
	}

	// Find k
	kAsBytes, err := findKValueFromLOCData(dlocDataToFindKFrom)
	if err != nil {
		return nil, fmt.Errorf("failed to find k value from DLOC ciphertexts: %v", err)
	}

	// Decrypt assignment data
	assignmentDatas := make([]types.AssignmentData, len(dlocDataToDecrypt))
	for i, d := range dlocDataToDecrypt {
		k_a, err := encryption.DecryptAES(kAsBytes, d.EncryptedKey())
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt EncryptedAssignmentDataKey at index %v: %v", i, err)
		}
		assignData, err := symDecryptAssignmentData(encryptedAssignmentData[i], k_a)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt assignment data at index %v: %v", i, err)
		}
		assignmentDatas[i] = assignData
	}

	return assignmentDatas, nil
}

func decryptLOCCiphertextsAndValidate(locCiphertexts [][]byte, locPrivateKey *rsa.PrivateKey) ([]types.LOCData, error) {
	// Decrypt loc ciphertexts
	locData, err := decryptLOCCiphertexts(locCiphertexts, locPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt LOC ciphertexts: %v", err)
	}

	// Validate
	if !validateLOCData(locData, types.Counselor) {
		return nil, fmt.Errorf("decrypted LOC ciphertexts but found non-Counselor data")
	}

	return locData, nil
}

// DecryptEntryData decrypts a list of encrypted entry data. It does this by
// finding a common k value amongst matched locData and attempting to decrypt
// encrypted entry keys with this k. It then uses the decrypted entry keys to
// decrypt all entry data.
func DecryptEntryData(locCiphertextsToFindKFrom [][]byte, locCiphertexts [][]byte, encryptedEntryData []encryption.GCMCiphertext, locPrivateKey *rsa.PrivateKey) ([]types.EntryData, error) {
	if len(locCiphertexts) != len(encryptedEntryData) {
		return nil, fmt.Errorf("mismatch length between locCiphertexts and encrypted entry data")
	}

	locDataToDecrypt, err := decryptLOCCiphertextsAndValidate(locCiphertexts, locPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt locCiphertexts: %v", err)
	}

	locDataToFindKFrom, err := decryptLOCCiphertextsAndValidate(locCiphertextsToFindKFrom, locPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt locCiphertextsToFindKFrom: %v", err)
	}

	// Find k
	kAsBytes, err := findKValueFromLOCData(locDataToFindKFrom)
	if err != nil {
		return nil, fmt.Errorf("failed to find k value from LOC ciphertexts: %v", err)
	}

	// Decrypt entry data
	entryDatas := make([]types.EntryData, len(locDataToDecrypt))
	for i, d := range locDataToDecrypt {
		k_e, err := encryption.DecryptAES(kAsBytes, d.EncryptedKey())
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt EncryptedEntryDataKey at index %v: %v", i, err)
		}
		entryData, err := symDecryptEntryData(encryptedEntryData[i], k_e)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt entry data at index %v: %v", i, err)
		}
		entryDatas[i] = entryData
	}

	return entryDatas, nil
}

func validateLOCData(data []types.LOCData, expectedLOCType types.LOCType) bool {
	for _, d := range data {
		if d.LocType() != expectedLOCType {
			return false
		}
	}
	return true
}

func decryptLOCCiphertexts(locCiphertexts [][]byte, privateKey *rsa.PrivateKey) ([]types.LOCData, error) {
	// Decrypt ciphertexts to get all loc data
	locData := make([]types.LOCData, len(locCiphertexts))
	for i, c := range locCiphertexts {
		decryptedCiphertext, err := decryptLOCCiphertext(c, privateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt (D)LOC ciphertext at index %v: %v", i, err)
		}
		locData[i] = decryptedCiphertext
	}

	return locData, nil
}

func findKValueFromLOCData(locData []types.LOCData) ([]byte, error) {
	// Form shamir (x,y) shares
	shares := make([]*ss.Share, len(locData))
	for i, d := range locData {
		shares[i] = d.GetShamirShare()
	}

	// Find K Value (the key)
	kAsElement, err := shamir.FindShamirKValue(shares)
	if err != nil {
		return nil, fmt.Errorf("failed to find k value: %v", err)
	}
	return kAsElement.Bytes(), nil
}

func decryptLOCCiphertext(locCiphertext []byte, privateKey *rsa.PrivateKey) (types.LOCData, error) {
	// Decrypt ciphertext
	dlocDataBytes, err := encryption.DecryptRSA(locCiphertext, privateKey)
	if err != nil {
		return types.LOCData{}, fmt.Errorf("failed to decrypt (D)LOC ciphertext: %v", err)
	}

	// Decode msgpack encoding of LOC data
	dlocData, err := encoding.DecodeLOCData(dlocDataBytes)
	if err != nil {
		return types.LOCData{}, err
	}

	return dlocData, nil
}

func symDecryptAssignmentData(encryptedAssignmentData encryption.GCMCiphertext, assignmentDataKey []byte) (types.AssignmentData, error) {
	// Decrypt assignment data
	assignmentDataEncodedBytes, err := encryption.DecryptAES(assignmentDataKey, encryptedAssignmentData)
	if err != nil {
		return types.AssignmentData{}, fmt.Errorf("failed to decrypt assignment data: %v", err)
	}

	// Decode msgpack encoding
	var decodedAssignmentData types.AssignmentData
	err = msgpack.Unmarshal(assignmentDataEncodedBytes, &decodedAssignmentData)
	if err != nil {
		return types.AssignmentData{}, fmt.Errorf("failed to decode assignment data: %v", err)
	}

	return decodedAssignmentData, nil
}

func symDecryptEntryData(encryptedEntryData encryption.GCMCiphertext, entryDataKey []byte) (types.EntryData, error) {
	// Decrypt entry data
	assignmentDataEncodedBytes, err := encryption.DecryptAES(entryDataKey, encryptedEntryData)
	if err != nil {
		return types.EntryData{}, fmt.Errorf("failed to decrypt entry data: %v", err)
	}

	// Decode msgpack encoding
	var decodedEntryData types.EntryData
	err = msgpack.Unmarshal(assignmentDataEncodedBytes, &decodedEntryData)
	if err != nil {
		return types.EntryData{}, fmt.Errorf("failed to decode entry data: %v", err)
	}

	return decodedEntryData, nil
}
