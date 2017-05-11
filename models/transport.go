package models

import (
	"github.com/bitly/go-simplejson"
	"gopkg.in/mgo.v2/bson"
)

type ReturnUAFRequest struct {
	StatusCode     uint64 `json:"statusCode"`
	UAFRequest     string `json:"uafRequest"`
	Operation      string `json:"op"`
	LifetimeMillis uint64 `json:"lifetimeMillis"`
}

type DeRegistrationRequest struct {
	Header         OperationHeader           `json:"header,omitempty" bson:"header"`
	Authenticators []DeRegisterAuthenticator `json:"authenticators,omitempty" bson:"authenticators"`
}

type MetaData struct {
	Name                        string   `json:"name,omitempty" bson:"name"`
	Aaid                        string   `json:"aaid,omitempty" bson:"aaid"`
	AttestationRootCertificates []string `json:"attestationRootCertificates,omitempty" bson:"attestationRootCertificates"`
	Description                 string   `json:"description,omitempty" bson:"description"`
	AuthenticatorVersion        uint16   `json:"authenticatorVersion,omitempty" bson:"authenticatorVersion"`
	UserVerificationDetails     [][]*struct {
		UserVerification int `json:"userVerification,omitempty" bson:"userVerification"`
	} `json:"userVerificationDetails,omitempty" bson:"userVerificationDetails"`
	AttachmentHint              int                                   `json:"attachmentHint,omitempty" bson:"attachmentHint"`
	KeyProtection               int                                   `json:"keyProtection,omitempty" bson:"keyProtection"`
	MatcherProtection           int                                   `json:"matcherProtection,omitempty" bson:"matcherProtection"`
	TcDisplay                   int                                   `json:"tcDisplay,omitempty" bson:"tcDisplay"`
	TcDisplayContentType        string                                `json:"tcDisplayContentType,omitempty" bson:"tcDisplayContentType"`
	IsSecondFactorOnly          bool                                  `json:"isSecondFactorOnly,omitempty" bson:"isSecondFactorOnly"`
	Icon                        string                                `json:"icon,omitempty" bson:"icon"`
	AssertionScheme             string                                `json:"assertionScheme,omitempty" bson:"assertionScheme"`
	AuthenticationAlgorithm     uint16                                `json:"authenticationAlgorithm,omitempty" bson:"authenticationAlgorithm"`
	PublicKeyAlgAndEncoding     int                                   `json:"publicKeyAlgAndEncoding,omitempty" bson:"publicKeyAlgAndEncoding"`
	AttestationTypes            []uint16                              `json:"attestationTypes,omitempty" bson:"attestationTypes"`
	Upv                         []*Version                            `json:"upv,omitempty" bson:"upv"`
	TcDisplayPNGCharacteristics []DisplayPNGCharacteristicsDescriptor `json:"tcDisplayPNGCharacteristics,omitempty" bson:"tcDisplayPNGCharacteristics"`
	Policies                    []string                              `json:"policies,omitempty" bson:"policies"`
}

type TrustedFacet struct {
	Version Version  `json:"version,omitempty" bson:"version"`
	Ids     []string `json:"ids,omitempty" bson:"ids"`
}
type Facet struct {
	ID            bson.ObjectId   `json:"id,omitempty" bson:"_id,omitempty"`
	AppID         string          `json:"appID,omitempty" bson:"appID"`
	TrustedFacets []*TrustedFacet `json:"trustedFacets,omitempty" bson:"trustedFacets"`
	Policies      []string        `json:"policies,omitempty" bson:"policies"`
}

type AuthenticatorData struct {
	PubKeyObject                []byte                                `json:"pubKeyObject,omitempty" bson:"pubKeyObject"`
	KeyID                       string                                `json:"keyID,omitempty" bson:"keyID"`
	SignatureCounter            int                                   `json:"signatureCounter,omitempty" bson:"signatureCounter"`
	AuthenticatorVersion        uint16                                `json:"authenticatorVersion,omitempty" bson:"authenticatorVersion"`
	Aaid                        string                                `json:"aaid,omitempty" bson:"aaid"`
	TcDisplayPNGCharacteristics []DisplayPNGCharacteristicsDescriptor `json:"tcDisplayPNGCharacteristics,omitempty" bson:"tcDisplayPNGCharacteristics"`
	Exts                        []Extension                           `json:"exts,omitempty" bson:"exts"`
}

type Authenticator struct {
	ID       bson.ObjectId      `json:"idm,omitempty" bson:"_id,omitempty"`
	Data     *AuthenticatorData `json:"data" bson:"data"`
	Username string             `json:"username" bson:"username"`
	Type     string             `json:"username" bson:"type"`
}

type Context struct {
	Transaction string `json:"transaction,omitempty" bson:"transaction"`
	UserName    string `json:"userName,omitempty" bson:"userName"`
}

type UAFRequest struct {
	Context Context   `json:"context,omitempty" bson:"context"`
	Op      Operation `json:"op,omitempty" bson:"op"`
}

type Challenge struct {
	ID          bson.ObjectId `json:"-" bson:"_id,omitempty"`
	Challenge   string        `json:"challenge,omitempty" bson:"challenge"`
	ServerData  string        `json:"serverData,omitempty" bson:"serverData"`
	Username    string        `json:"username,omitempty" bson:"username"`
	Policy      *Policy       `json:"policy,omitempty" bson:"policy"`
	Expiration  int           `json:"expiration,omitempty" bson:"expiration"`
	Transaction string        `json:"transaction,omitempty" bson:"transaction"`
}

type AuthPolicy struct {
	Name   string `json:"name,omitempty" bson:"name"`
	Policy Policy `json:"policy,omitempty" bson:"policy"`
}

type AssertionObject struct {
	Assertion                   *simplejson.Json
	AssertionBuffer             []byte
	TcDisplayPNGCharacteristics []DisplayPNGCharacteristicsDescriptor
	Exts                        []Extension
}
