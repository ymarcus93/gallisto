package types

// The ciphersuite used for the OPRF protocol
const OPRF_CIPHERSUITE string = "OPRF-P521-HKDF-SHA512-SSWU-RO"

// EntryData encapsulates information about the perpetrator and the victim.
// EntryData is only meant to be viewed by LOCs.
type EntryData struct {
	PerpetratorName            string
	PerpetratorTwitterUserName string
	VictimName                 string
	VictimPhoneNumber          string
	VictimEmail                string
}

// AssignmentData encapsulates the necessary information for DLOCs to assign
// matched users to LOCs. AssignmentData is onnly meant to be viewed by DLOCs.
type AssignmentData struct {
	VictimStateOfCurrentResidence    string
	CategorizationOfSexualMisconduct string
	IndustryOfPerpetrator            string
}

// An enum that represents the type of LOC
type LOCType int

const (
	Unknown   LOCType = iota // Default case
	Director                 // Also known as DLOC
	Counselor                // Also known as LOC
)
