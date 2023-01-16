// Copyright 2023 The Go SSI Framework Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package diddoc

import (
	"time"
)

type ProofPurpose string

const (
	AssertionMethod      ProofPurpose = "assertionMethod"
	Authentication       ProofPurpose = "authentication"
	KeyAgreement         ProofPurpose = "keyAgreement"
	CapabilityInvocation ProofPurpose = "capabilityInvocation"
	CapabilityDelegation ProofPurpose = "capabilityDelegation"
)

func (p ProofPurpose) String() string {
	return string(p)
}

// DocumentMetadata document metadata, consist of the REQUIRED attributes.
type DocumentMetadata struct {
	// Deactivated is deactivated flag key.
	Deactivated bool `json:"deactivated"`
}

type Context []string

type Proof struct {
	Type               string       `json:"type,omitempty"`
	Created            time.Time    `json:"created,omitempty"`
	VerificationMethod string       `json:"verificationMethod,omitempty"`
	ProofPurpose       ProofPurpose `json:"proofPurpose,omitempty"`
	Nonce              string       `json:"nonce,omitempty"`
	ProofValue         *string      `json:"jws,omitempty"`
}

type VerificationMethod struct {
	Id                 string      `json:"id,omitempty"`
	Type               string      `json:"type,omitempty"`
	Controller         string      `json:"controller,omitempty"`
	PubicKeyJWK        interface{} `json:"publicKeyJwk,omitempty"`
	PublicKeyMultibase string      `json:"publicKeyMultibase,omitempty"`
}

type VerificationRelation interface{}

type Service struct {
	Id              string `json:"id"`
	Type            string `json:"type"`
	ServiceEndpoint string `json:"serviceEndpoint"`
}
