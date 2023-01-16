// Copyright 2023 The Go SSI Framework Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package diddoc

import (
	"encoding/json"
	"errors"
	"reflect"
	"sync"
)

const (
	contextKey              string = "@context"
	subjectKey              string = "id"
	alsoKnownAsKey          string = "alsoKnownAs"
	controllerKey           string = "controller"
	verificationMethodKey   string = "verificationMethod"
	authenticationKey       string = "authentication"
	assertionMethodKey      string = "assertionMethod"
	keyAgreementKey         string = "keyAgreement"
	capabilityInvocationKey string = "capabilityInvocation"
	capabilityDelegationKey string = "capabilityDelegation"
	serviceKey              string = "service"
)

var (
	errNotFound    error = errors.New("not_found")
	errInvalidType error = errors.New("invalid_type_conversion")
)

// MapItem representation of one map item.
type MapItem struct {
	Key, Value interface{}
}

// MapSlice of map items.
type MapSlice []MapItem

// didDocument holds the properties, the metadsata, and options for document resolution
type Document struct {
	mu         *sync.RWMutex
	properties MapSlice
}

// NewDocument creates a document instance
func NewDocument() *Document {
	return &Document{
		mu:         &sync.RWMutex{},
		properties: nil,
	}
}

// Context gets the context property of the document
func (d *Document) Context() interface{} {
	return d.Get(contextKey)
}

// Subject gets the did subject property of the document
func (d *Document) Subject() interface{} {
	return d.Get(subjectKey)
}

// AlsoKnownAs gets the alsoKnownAs property of the document
func (d *Document) AlsoKnownAs() interface{} {
	return d.Get(alsoKnownAsKey)
}

// Controller gets the controller property of the document
func (d *Document) Controller() interface{} {
	return d.Get(controllerKey)
}

// VerificationMethod gets the verificationMethod property of the document
func (d *Document) VerificationMethod() interface{} {
	return d.Get(verificationMethodKey)
}

// Authentication gets the authentication property of the document
func (d *Document) Authentication() interface{} {
	return d.Get(authenticationKey)
}

// AssertionMethod gets the assertionMethod property of the document
func (d *Document) AssertionMethod() interface{} {
	return d.Get(assertionMethodKey)
}

// KeyAgreement gets the keyAgreement property of the document
func (d *Document) KeyAgreement() interface{} {
	return d.Get(keyAgreementKey)
}

// CapabilityInvocation gets the capabilityInvocation property of the document
func (d *Document) CapabilityInvocation() interface{} {
	return d.Get(capabilityInvocationKey)
}

// CapabilityDelegation gets the capabilityDelegation property of the document
func (d *Document) CapabilityDelegation() interface{} {
	return d.Get(capabilityDelegationKey)
}

// Services gets the services property of the document
func (d *Document) Services() interface{} {
	return d.Get(serviceKey)
}

// Metadata gets the metadata of the document
func (d *Document) Metadata() DocumentMetadata {
	return DocumentMetadata{
		Deactivated: false,
	}
}

// Get gets the value of the property with a key
func (d *Document) Get(key string) interface{} {
	for _, prop := range d.properties {
		if prop.Key == key {
			return prop.Value
		}
	}
	return nil
}

// Set sets the value of the property with a key
func (d *Document) Set(key, value interface{}) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	property := MapItem{Key: key, Value: value}
	d.properties = append(d.properties, property)
	return nil
}

// GetAssociatedVerificationMethod gets the associated verification method for a purpose
func (d *Document) GetAssociatedVerificationMethod(purpose ProofPurpose) ([]VerificationMethod, error) {
	var response []VerificationMethod
	responseValue := reflect.ValueOf(&response).Elem()

	verificationRelation := d.Get(purpose.String())
	if verificationRelation != nil {
		v := reflect.ValueOf(verificationRelation)

		switch v.Kind() {
		case reflect.Slice, reflect.Array:
			for i := 0; i < v.Len(); i++ {

				if err := d.addVerificationMethod(v.Index(i), responseValue); err != nil {
					return []VerificationMethod{}, err
				}
			}
		}
		switch resp := responseValue.Interface().(type) {
		case []VerificationMethod:
			if len(response) > 0 {
				return resp, nil
			}
			return []VerificationMethod{}, errNotFound
		default:
			return []VerificationMethod{}, errInvalidType
		}
	}
	return []VerificationMethod{}, errNotFound
}

func (d *Document) GetVerificationMethodById(keyId string) (VerificationMethod, error) {
	var response VerificationMethod
	responseValue := reflect.ValueOf(&response).Elem()

	verificationMehods := d.Get(verificationMethodKey)
	if verificationMehods != nil {
		v := reflect.ValueOf(verificationMehods)

		switch v.Kind() {
		case reflect.Slice, reflect.Array:
			for i := 0; i < v.Len(); i++ {
				if d.verificationMethodFound(v.Index(i), keyId, responseValue) {

					switch resp := responseValue.Interface().(type) {
					case VerificationMethod:
						return resp, nil
					default:
						return VerificationMethod{}, errInvalidType
					}
				}
			}
		}
	}
	return VerificationMethod{}, errNotFound
}

func (d *Document) verificationMethodFound(iteratorValue reflect.Value, keyId string, foundValue reflect.Value) bool {
	switch iteratorValue.Kind() {
	case reflect.Struct:
		if iteratorValue.FieldByName("Id").String() == keyId {
			foundValue.Set(iteratorValue)
			return true
		}
	case reflect.Interface:
		return d.verificationMethodFound(iteratorValue.Elem(), keyId, foundValue)
	}
	return false
}

func (d *Document) addVerificationMethod(iteratorValue reflect.Value, foundValue reflect.Value) error {
	switch iteratorValue.Kind() {
	case reflect.Map:
		var verificatiobMethod VerificationMethod
		verificationMethodValue := reflect.ValueOf(&verificatiobMethod).Elem()
		verificationMethodType := reflect.TypeOf(&verificatiobMethod).Elem()

		if err := structEncoder(verificationMethodValue, verificationMethodType, iteratorValue); err != nil {
			return err
		}
		foundValue.Set(reflect.Append(foundValue, verificationMethodValue))

	case reflect.String:
		verificationMethod, err := d.GetVerificationMethodById(iteratorValue.String())
		if err != nil {
			return nil //no error, verificatiod might be revoked
		}
		foundValue.Set(reflect.Append(foundValue, reflect.ValueOf(verificationMethod)))

	case reflect.Struct:
		foundValue.Set(reflect.Append(foundValue, iteratorValue))

	case reflect.Interface:
		if err := d.addVerificationMethod(iteratorValue.Elem(), foundValue); err != nil {
			return err
		}
	}
	return nil
}

func (d *Document) MarshalJSON() ([]byte, error) {
	mapKeyValue := map[string]interface{}{}
	for _, prop := range d.properties {
		switch prop.Key.(string) {
		case subjectKey:
			mapKeyValue[prop.Key.(string)] = prop.Value
		case contextKey, controllerKey:
			value := prop.Value.([]string)
			if len(value) > 1 {
				mapKeyValue[prop.Key.(string)] = prop.Value
			} else {
				mapKeyValue[prop.Key.(string)] = value[0]
			}
		case alsoKnownAsKey:
			mapKeyValue[prop.Key.(string)] = prop.Value
		case verificationMethodKey:
			mapKeyValue[prop.Key.(string)] = prop.Value
		case authenticationKey, assertionMethodKey, keyAgreementKey, capabilityInvocationKey, capabilityDelegationKey:
			mapKeyValue[prop.Key.(string)] = prop.Value
		case serviceKey:
			mapKeyValue[prop.Key.(string)] = prop.Value
		}
	}
	return json.Marshal(mapKeyValue)
}

func (d *Document) UnmarshalJSON(data []byte) error {
	properties := map[string]interface{}{}
	err := json.Unmarshal(data, &properties)
	if err != nil {
		return err
	}
	b := NewBuilder()
	for key, value := range properties {
		switch key {
		case contextKey, alsoKnownAsKey, controllerKey:
			b.stringArray(key, value)
		case subjectKey:
			b.Subject(value)
		case verificationMethodKey:
			b.VerificationMethod(value)
		case authenticationKey,
			assertionMethodKey,
			keyAgreementKey,
			capabilityInvocationKey,
			capabilityDelegationKey:
			b.verificationRelationArray(key, value)
		case serviceKey:
			b.Service(value)
		default:
			b.CustomProperty(key, value)
		}
	}
	doc, err := b.Build()
	if err != nil {
		return err
	}
	d.properties = doc.properties
	return nil
}
