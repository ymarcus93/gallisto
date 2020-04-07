package encoding

import (
	"fmt"

	"github.com/vmihailenco/msgpack"
	"github.com/ymarcus93/gallisto/types"
)

// EncodeEntryData returns a msgpack encoding of Callisto entry data
func EncodeEntryData(entryData types.EntryData) ([]byte, error) {
	// Create msgpack encoding of entry data
	entryDataEncodedBytes, err := msgpack.Marshal(&entryData)
	if err != nil {
		return nil, fmt.Errorf("failed to encode entry data: %v", err)
	}

	return entryDataEncodedBytes, nil
}

// DecodeEntryData decodes msgpack encoding of Callisto entry data
func DecodeEntryData(encodedEntryData []byte) (types.EntryData, error) {
	// Decode msgpack encoding of entry data
	var decodedEntryData types.EntryData
	err := msgpack.Unmarshal(encodedEntryData, &decodedEntryData)
	if err != nil {
		return types.EntryData{}, fmt.Errorf("failed to decode entry data: %v", err)
	}

	return decodedEntryData, nil
}

// EncodeAssignmentData returns a msgpack encoding of Callisto assignment data
func EncodeAssignmentData(assignData types.AssignmentData) ([]byte, error) {
	// Create msgpack encoding of assignment data
	assignmentDataEncodedBytes, err := msgpack.Marshal(&assignData)
	if err != nil {
		return nil, fmt.Errorf("failed to encode assignment data: %v", err)
	}

	return assignmentDataEncodedBytes, nil
}

// DecodeAssignmentData decodes msgpack encoding of Callisto assignment data
func DecodeAssignmentData(encodedAssignmentData []byte) (types.AssignmentData, error) {
	// Decode msgpack encoding of assignment data
	var decodedAssignmentData types.AssignmentData
	err := msgpack.Unmarshal(encodedAssignmentData, &decodedAssignmentData)
	if err != nil {
		return types.AssignmentData{}, fmt.Errorf("failed to decode assignment data: %v", err)
	}

	return decodedAssignmentData, nil
}

// EncodeLOCData returns a msgpack encoding of LOC data
func EncodeLOCData(locData types.LOCData) ([]byte, error) {
	// Create msgpack encoding of LOC data
	locDataEncodedBytes, err := msgpack.Marshal(&locData)
	if err != nil {
		return nil, fmt.Errorf("failed to encode LOC data: %v", err)
	}

	return locDataEncodedBytes, nil
}

// DecodeLOCData decodes msgpack encoding of LOC data
func DecodeLOCData(encodedLOCData []byte) (types.LOCData, error) {
	// Decode msgpack encoding of LOC data
	var decodedLOCData types.LOCData
	err := msgpack.Unmarshal(encodedLOCData, &decodedLOCData)
	if err != nil {
		return types.LOCData{}, fmt.Errorf("failed to decode LOC data: %v", err)
	}

	return decodedLOCData, nil
}

// EncodeDLOCData returns a msgpack encoding of DLOC data
func EncodeDLOCData(dlocData types.DLOCData) ([]byte, error) {
	// Create msgpack encoding of LOC data
	dlocDataEncodedBytes, err := msgpack.Marshal(&dlocData)
	if err != nil {
		return nil, fmt.Errorf("failed to encode DLOC data: %v", err)
	}

	return dlocDataEncodedBytes, nil
}

// DecodeDLOCData decodes msgpack encoding of DLOC data
func DecodeDLOCData(encodedDLOCData []byte) (types.DLOCData, error) {
	// Decode msgpack encoding of LOC data
	var decodedDLOCData types.DLOCData
	err := msgpack.Unmarshal(encodedDLOCData, &decodedDLOCData)
	if err != nil {
		return types.DLOCData{}, fmt.Errorf("failed to decode DLOC data: %v", err)
	}

	return decodedDLOCData, nil
}
