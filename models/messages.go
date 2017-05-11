package models

import (
	"encoding/json"
)

type Version struct {
	Major json.Number `json:"major" bson:"major" validate:"eq=1"`
	Minor json.Number `json:"minor,omitempty" bson:"minor" validate:"eq=0"`
}

type OperationHeader struct {
	Upv        Version      `json:"upv,omitempty"bson:"upv"`               // UAF protocol version (upv). To conform with this version of the UAF spec set, the major value must be 1 and the minor value must be 1.
	Op         Operation    `json:"op,omitempty"bson:"op"`                 // Name of FIDO operation (op) this message relates to.
	AppID      string       `json:"appID,omitempty"bson:"appID"`           // The application identifier that the relying party would like to assert.
	ServerData string       `json:"serverData,omitempty"bson:"serverData"` // A session identifier created by the relying party.
	Exts       []*Extension `json:"exts,omitempty"bson:"exts"`             // List of UAF Message Extensions.
}

// FinalChallengeParams
type FinalChallengeParams struct {
	AppID          string         `json:"appID,omitempty"bson:"appID"`                   // The value must be taken from the appID field of the OperationHeader
	Challenge      string         `json:"challenge,omitempty"bson:"challenge"`           // The value must be taken from the challenge field of the request (e.g. RegistrationRequest.challenge, AuthenticationRequest.challenge).
	FacetID        string         `json:"facetID,omitempty"bson:"facetID"`               // The value is determined by the FIDO UAF Client and it depends on the calling application
	ChannelBinding ChannelBinding `json:"channelBinding,omitempty"bson:"channelBinding"` // Contains the TLS information to be sent by the FIDO Client to the FIDO Server
}

// ChannelBinding contains channel binding information
type ChannelBinding struct {
	ServerEndPoint       string `json:"serverEndPoint,omitempty"bson:"serverEndPoint"`
	TlsServerCertificate string `json:"tlsServerCertificate,omitempty"bson:"tlsServerCertificate"`
	TlsUnique            string `json:"tlsUnique,omitempty"bson:"tlsUnique"`
	CIDPubkey            string `json:"cid_pubkey,omitempty"bson:"cid_pubkey"`
}

//JwkKey is a dictionary representing a JSON Web Key encoding of an elliptic curve public key
type JwkKey struct {
	Kty string `json:"kty,omitempty"bson:"kty"`
	Crv string `json:"crv,omitempty"bson:"crv"`
	X   string `json:"x,omitempty"bson:"x"`
	Y   string `json:"y,omitempty"bson:"y"`
}

// Initialize jwkkey with defaults
func (self *JwkKey) init() {
	self.Kty = "EC"
	self.Crv = "P-256"
}

// Generic extensions used in various operations.
type Extension struct {
	Id            string `json:"id,omitempty"bson:"id"`                           // extension Identifier.
	Data          string `json:"data,omitempty"bson:"data"`                       // Contains arbitrary data with a semantics agreed between server and client. Binary data is base64url-encoded.
	FailIfUnknown bool   `json:"fail_if_unknown,omitempty"bson:"fail_if_unknown"` // Indicates whether unknown extensions must be ignored (false) or must lead to an error (true).
}

//Represents the matching criteria to be used in the server policy.
//The MatchCriteria object is considered to match an authenticator
type MatchCriteria struct {
	Aaid                     []string     `json:"aaid,omitempty"bson:"aaid"`
	VendorID                 []string     `json:"vendorID,omitempty"bson:"vendorID"`
	KeyIDs                   []string     `json:"keyIDs,omitempty"bson:"keyIDs"`
	UserVerification         uint64       `json:"userVerification,omitempty"bson:"userVerification"`
	KeyProtection            int          `json:"keyProtection,omitempty"bson:"keyProtection"`
	MatcherProtection        int          `json:"matcherProtection,omitempty"bson:"matcherProtection"`
	AttachmentHint           uint64       `json:"attachmentHint,omitempty"bson:"attachmentHint"`
	TcDisplay                int          `json:"tcDisplay,omitempty"bson:"tcDisplay"`
	AuthenticationAlgorithms []int        `json:"authenticationAlgorithms,omitempty"bson:"authenticationAlgorithms"`
	AssertionSchemes         []string     `json:"assertionSchemes,omitempty"bson:"assertionSchemes"`
	AttestationTypes         []int        `json:"attestationTypes,omitempty"bson:"attestationTypes"`
	AuthenticatorVersion     uint16       `json:"authenticatorVersion,omitempty"bson:"authenticatorVersion"`
	Exts                     []*Extension `json:"exts,omitempty"bson:"exts"`
}

// Contains a specification of accepted authenticators and a specification of disallowed authenticators.
type Policy struct {
	Name       string             `json:"name,omitempty"bson:"name"`
	Accepted   [][]*MatchCriteria `json:"accepted,omitempty"bson:"accepted"`
	Disallowed []*MatchCriteria   `json:"disallowed,omitempty"bson:"disallowed"`
}

// RegistrationRequest contains a single, versioned, registration request.
type RegistrationRequest struct {
	Header    OperationHeader `json:"header,omitempty"bson:"header"`
	Challenge string          `json:"challenge,omitempty"bson:"challenge"`
	Username  string          `json:"username,omitempty"bson:"username"`
	Policy    *Policy         `json:"policy,omitempty"bson:"policy"`
}

type Assertion struct {
	AssertionScheme             string                                `json:"assertionScheme,omitempty"bson:"assertionScheme"`
	Assertion                   string                                `json:"assertion,omitempty"bson:"assertion"`
	TcDisplayPNGCharacteristics []DisplayPNGCharacteristicsDescriptor `json:"tcDisplayPNGCharacteristics,omitempty"bson:"tcDisplayPNGCharacteristics"`
	Exts                        []Extension                           `json:"exts,omitempty"bson:"exts"`
}

// Contains the authenticator's response to a RegistrationRequest message:
type AuthenticatorRegistrationAssertion struct {
	AssertionScheme             string                                `json:"assertionScheme,omitempty"bson:"assertionScheme"`
	Assertion                   string                                `json:"assertion,omitempty"bson:"assertion"`
	TcDisplayPNGCharacteristics []DisplayPNGCharacteristicsDescriptor `json:"tcDisplayPNGCharacteristics,omitempty"bson:"tcDisplayPNGCharacteristics"`
	Exts                        []Extension                           `json:"exts,omitempty"bson:"exts"`
}

type UAFResponse interface {
	GetFcParams() string
	GetHeader() *OperationHeader
	GetAssertion(index int) *Assertion
}

// Contains all fields related to the registration response.
type RegistrationResponse struct {
	Header     OperationHeader `json:"header,omitempty"bson:"header"`
	FcParams   string          `json:"fcParams,omitempty"bson:"fcParams"`
	Assertions []*Assertion    `json:"assertions,omitempty"bson:"assertions"`
}

func (a *RegistrationResponse) GetFcParams() string {
	return a.FcParams
}

func (a *RegistrationResponse) GetHeader() *OperationHeader {
	return &a.Header
}

func (a *RegistrationResponse) GetAssertion(index int) *Assertion {
	return a.Assertions[index]
}

type RGBPalletteEntry struct {
	R uint8 `json:"r,omitempty"bson:"r"`
	G uint8 `json:"g,omitempty"bson:"g"`
	B uint8 `json:"b,omitempty"bson:"b"`
}
type DisplayPNGCharacteristicsDescriptor struct {
	Width       uint64              `json:"width,omitempty"bson:"width"`
	Height      uint64              `json:"height,omitempty"bson:"height"`
	BitDepth    uint32              `json:"bitDepth,omitempty"bson:"bitDepth"`
	ColorType   uint32              `json:"colorType,omitempty"bson:"colorType"`
	Compression uint32              `json:"compression,omitempty"bson:"compression"`
	Filter      uint32              `json:"filter,omitempty"bson:"filter"`
	Interlace   uint32              `json:"interlace,omitempty"bson:"interlace"`
	Plte        []*RGBPalletteEntry `json:"plte,omitempty"bson:"plte"`
}
type Transaction struct {
	ContentType                 string                              `json:"contentType,omitempty"bson:"contentType"`
	Content                     string                              `json:"content,omitempty"bson:"content"`
	TcDisplayPNGCharacteristics DisplayPNGCharacteristicsDescriptor `json:"tcDisplayPNGCharacteristics,omitempty"bson:"tcDisplayPNGCharacteristics"`
}

type AuthenticationRequest struct {
	Header      OperationHeader `json:"header,omitempty"bson:"header"`
	Challenge   string          `json:"challenge,omitempty"bson:"challenge"`
	Transaction []Transaction   `json:"transaction,omitempty"bson:"transaction"`
	Policy      *Policy         `json:"policy,omitempty"bson:"policy"`
}

type AuthenticatorSignAssertion struct {
	AssertionScheme string      `json:"assertionScheme,omitempty"bson:"assertionScheme"`
	Assertion       string      `json:"assertion,omitempty"bson:"assertion"`
	Exts            []Extension `json:"exts,omitempty"bson:"exts"`
}

type AuthenticationResponse struct {
	Header     OperationHeader `json:"header,omitempty"bson:"header"`
	FcParams   string          `json:"fcParams,omitempty"bson:"fcParams"`
	Assertions []*Assertion    `json:"assertions,omitempty"bson:"assertions"`
}

func (a *AuthenticationResponse) GetFcParams() string {
	return a.FcParams
}

func (a *AuthenticationResponse) GetHeader() *OperationHeader {
	return &a.Header
}

func (a *AuthenticationResponse) GetAssertion(index int) *Assertion {
	return a.Assertions[index]
}

type DeRegisterAuthenticator struct {
	Aaid  string `json:"aaid,omitempty"bson:"aaid"`
	KeyID string `json:"keyID,omitempty"bson:"keyID"`
}

var UAF_ALG_SIGN = map[uint16]string{
	UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW: "UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW",
	UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_DER: "UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_DER",
	UAF_ALG_SIGN_RSASSA_PSS_SHA256_RAW:      "UAF_ALG_SIGN_RSASSA_PSS_SHA256_RAW",
	UAF_ALG_SIGN_RSASSA_PSS_SHA256_DER:      "UAF_ALG_SIGN_RSASSA_PSS_SHA256_DER",
	UAF_ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW: "UAF_ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW",
	UAF_ALG_SIGN_SECP256K1_ECDSA_SHA256_DER: "UAF_ALG_SIGN_SECP256K1_ECDSA_SHA256_DER",
}
var UAF_ALG_KEY = map[uint16]string{
	UAF_ALG_KEY_ECC_X962_RAW:     "UAF_ALG_KEY_ECC_X962_RAW",
	UAF_ALG_KEY_ECC_X962_DER:     "UAF_ALG_KEY_ECC_X962_DER",
	UAF_ALG_KEY_RSA_2048_PSS_RAW: "UAF_ALG_KEY_RSA_2048_PSS_RAW",
	UAF_ALG_KEY_RSA_2048_PSS_DER: "UAF_ALG_KEY_RSA_2048_PSS_DER",
}

var AUTHENTICATION_MODE = []int{
	0x01,
	0x02,
}

type Operation string

const (
	Unknown Operation = "Unknown"
	Reg               = "Reg"
	Auth              = "Auth"
	Dereg             = "Dereg"

	//defines all the constants and types for uaf
	VERSION = "v1.0"

	//Key Protection Types
	KEY_PROTECTION_SOFTWARE       = 0x01
	KEY_PROTECTION_HARDWARE       = 0x02
	KEY_PROTECTION_TEE            = 0x04
	KEY_PROTECTION_SECURE_ELEMENT = 0x08
	KEY_PROTECTION_REMOTE_HANDLE  = 0x10

	//User Verification Methods
	USER_VERIFY_PRESENCE    = 0x01
	USER_VERIFY_FINGERPRINT = 0x02
	USER_VERIFY_PASSCODE    = 0x04
	USER_VERIFY_VOICEPRINT  = 0x08
	USER_VERIFY_FACEPRINT   = 0x10
	USER_VERIFY_LOCATION    = 0x20
	USER_VERIFY_EYEPRINT    = 0x40
	USER_VERIFY_PATTERN     = 0x80
	USER_VERIFY_HANDPRINT   = 0x100
	USER_VERIFY_NONE        = 0x200
	USER_VERIFY_ALL         = 0x400

	//Matcher Protection Types
	MATCHER_PROTECTION_SOFTWARE = 0x01
	MATCHER_PROTECTION_TEE      = 0x02
	MATCHER_PROTECTION_ON_CHIP  = 0x04

	//Authenticator Attachment Hints
	ATTACHMENT_HINT_INTERNAL    = 0x01
	ATTACHMENT_HINT_EXTERNAL    = 0x02
	ATTACHMENT_HINT_WIRED       = 0x04
	ATTACHMENT_HINT_WIRELESS    = 0x08
	ATTACHMENT_HINT_NFC         = 0x10
	ATTACHMENT_HINT_BLUETOOTH   = 0x20
	ATTACHMENT_HINT_NETWORK     = 0x40
	ATTACHMENT_HINT_READY       = 0x80
	ATTACHMENT_HINT_WIFI_DIRECT = 0x100

	//Transaction Confirmation Display Types
	TRANSACTION_CONFIRMATION_DISPLAY_ANY                 = 0x01
	TRANSACTION_CONFIRMATION_DISPLAY_PRIVILEGED_SOFTWARE = 0x02
	TRANSACTION_CONFIRMATION_DISPLAY_TEE                 = 0x04
	TRANSACTION_CONFIRMATION_DISPLAY_HARDWARE            = 0x08
	TRANSACTION_CONFIRMATION_DISPLAY_REMOTE              = 0x10

	//Tags used for crypto algorithms and types //authentication algorithm
	UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW = 0x01
	UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_DER = 0x02
	UAF_ALG_SIGN_RSASSA_PSS_SHA256_RAW      = 0x03
	UAF_ALG_SIGN_RSASSA_PSS_SHA256_DER      = 0x04
	UAF_ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW = 0x05
	UAF_ALG_SIGN_SECP256K1_ECDSA_SHA256_DER = 0x06

	//Public Key Representation Formats //public key format
	UAF_ALG_KEY_ECC_X962_RAW     = 0x100 //256
	UAF_ALG_KEY_ECC_X962_DER     = 0x101 //257
	UAF_ALG_KEY_RSA_2048_PSS_RAW = 0x102 //258
	UAF_ALG_KEY_RSA_2048_PSS_DER = 0x103 //259

	//UAF Status Codes
	OPERATION_COMPLETED              = 1200
	MESSAGE_ACCEPTED                 = 1202
	BAD_REQUEST                      = 1400
	UNAUTHORIZED                     = 1401
	FORBIDDEN                        = 1403
	NOT_FOUND                        = 1404
	REQUEST_TIMEOUT                  = 1408
	UNKOWN_AAID                      = 1480
	UNKOWN_KEYID                     = 1481
	CHANNEL_BINDING_REFUSED          = 1490
	INVALID_REQUEST                  = 1491
	UNACCEPTABLE_AUTHENTICATOR       = 1492
	REVOKED_AUTHENTICATOR            = 1493
	UNACCEPTABLE_KEY                 = 1494
	UNACCEPTABLE_ALGORITHM           = 1495
	UNACCEPTABLE_ATTESTATION         = 1496
	UNACCEPTABLE_CLIENT_CAPABILITIES = 1497
	UNACCEPTABLE_CONTENT             = 1498
	INTERNAL_SERVER_ERROR            = 1500
)
