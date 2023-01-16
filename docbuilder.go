// Copyright 2023 The Go SSI Framework Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package diddoc

import (
	"fmt"
)

// BuilderItem representation of one map item.
type BuilderItem struct {
	Key, Value interface{}
}

// MapSlice of map items.
type BuilderSlice []BuilderItem

type builder struct {
	properties BuilderSlice
}

func NewBuilder() *builder {
	return &builder{}
}

// Property sets the value for a key.
func (b *builder) property(key string, value interface{}) *builder {
	if value != nil {
		b.properties = append(b.properties, BuilderItem{Key: key, Value: value})
	}
	return b
}

func (b *builder) verificationRelationArray(key string, v interface{}) *builder {
	var d []VerificationRelation
	err := encode(&d, v)
	if err != nil {
		panic(err)
	}
	return b.property(key, d)
}

func (b *builder) stringArray(key string, v interface{}) *builder {
	var d []string
	err := encode(&d, v)
	if err != nil {
		panic(err)
	}
	return b.property(key, d)
}

// Context is used as JSON-LD Context.
// The value of MUST be a string or a list containing any combination of strings and/or ordered maps.
func (b *builder) Context(v interface{}) *builder {
	return b.stringArray(contextKey, v)
}

// Subject is the DID for a particular DID subject.
// The value of MUST be a string that conforms to the rules in 3.1 DID Syntax.
func (b *builder) Subject(v interface{}) *builder {
	var d string
	err := encode(&d, v)
	if err != nil {
		panic(err)
	}
	return b.property(subjectKey, d)
}

// AlsoKnownAs is a statement that the subject of this identifier is also identified by one or more other identifiers.
// The value MUST be a set where each item in the set is a URI conforming to [RFC3986].
func (b *builder) AlsoKnownAs(v interface{}) *builder {
	return b.stringArray(alsoKnownAsKey, v)
}

// Controller is the DID controller, an entity that is authorized to make changes to a DID document.
// The value MUST be a string or a set of strings that conform to the rules in 3.1 DID Syntax.
func (b *builder) Controller(v interface{}) *builder {
	return b.stringArray(controllerKey, v)
}

// VerificationMethods are cryptographic public keys, which can be used to authenticate or authorize interactions with the DID subject or associated parties.
// The value MUST be a verification method or a set of verification methods.
func (b *builder) VerificationMethod(v interface{}) *builder {
	var d []VerificationMethod
	err := encode(&d, v)
	if err != nil {
		panic(err)
	}
	return b.property(verificationMethodKey, d)
}

// Authentication is a verification relationship used to specify how the DID subject is expected to be authenticated.
func (b *builder) Authentication(v interface{}) *builder {
	return b.verificationRelationArray(authenticationKey, v)
}

// AssertionMethod is a verification relationship used to specify how the DID subject is expected to assert proof,
// such as for the purposes of asserting the proof of a Verifiable Credential
func (b *builder) AssertionMethod(v interface{}) *builder {
	return b.verificationRelationArray(assertionMethodKey, v)
}

// KeyAgreement is a verification relationship used to specify how an entity can generate encryption material.
func (b *builder) KeyAgreement(v interface{}) *builder {
	return b.verificationRelationArray(keyAgreementKey, v)
}

// CapabilityInvocation is a verification relationship used to specify a verification method that might be used by the DID subject to invoke a cryptographic capability.
func (b *builder) CapabilityInvocation(v interface{}) *builder {
	return b.verificationRelationArray(capabilityInvocationKey, v)
}

// CapabilityDelegation is a verification relationship used to specify a mechanism that might be used by the DID subject to delegate a cryptographic capability to another party.
func (b *builder) CapabilityDelegation(v interface{}) *builder {
	return b.verificationRelationArray(capabilityDelegationKey, v)
}

// Service is used in a DID documents to express ways of communicating with the DID subject or associated entities.
func (b *builder) Service(v interface{}) *builder {
	var d []Service
	err := encode(&d, v)
	if err != nil {
		panic(err)
	}
	return b.property(serviceKey, d)
}

func (b *builder) CustomProperty(key string, v interface{}) *builder {
	return b.property(key, v)
}

// Build creates a new token based on the claims that the builder has received
// so far. If a claim cannot be set, then the method returns a nil Token with
// a en error as a second return value
func (b *builder) Build() (Document, error) {
	doc := NewDocument()
	for _, property := range b.properties {
		if err := doc.Set(property.Key, property.Value); err != nil {
			return *doc, fmt.Errorf("failed to set property %q: %w", property.Key, err)
		}
	}
	return *doc, nil
}
