// Copyright 2023 The Go SSI Framework Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package diddoc_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/gossif/diddoc"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
)

func TestArrayStringValue(t *testing.T) {
	type errorTestCases struct {
		description    string
		inputValue     interface{}
		expectedOutput interface{}
		expectedError  string
	}
	for _, scenario := range []errorTestCases{
		{description: "arraystring to arraystring", inputValue: []string{"https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/ed25519-2020/v1"},
			expectedOutput: []string{"https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/ed25519-2020/v1"}, expectedError: ""},
		{description: "interface to arraystring", inputValue: []interface{}{"https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/ed25519-2020/v1"},
			expectedOutput: []string{"https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/ed25519-2020/v1"}, expectedError: ""},
		{description: "string to arraystring", inputValue: "https://www.w3.org/ns/did/v1", expectedOutput: []string{"https://www.w3.org/ns/did/v1"}, expectedError: ""},
		{description: "bytes to arraystring", inputValue: []byte("https://www.w3.org/ns/did/v1"), expectedOutput: []string{"https://www.w3.org/ns/did/v1"}, expectedError: ""},
	} {
		t.Run(scenario.description, func(t *testing.T) {

			doc, _ := diddoc.NewBuilder().Context(scenario.inputValue).Build()
			actualOutput := doc.Context()

			assert.EqualValues(t, scenario.expectedOutput, actualOutput)
			assert.EqualValues(t, "[]string", reflect.TypeOf(actualOutput).String())
		})
	}
}

func TestStringValue(t *testing.T) {
	type errorTestCases struct {
		description    string
		inputValue     interface{}
		expectedOutput interface{}
		expectedType   string
		expectedError  string
	}
	for _, scenario := range []errorTestCases{
		{description: "string to string", inputValue: "stringvalue", expectedOutput: "stringvalue", expectedType: "string", expectedError: ""},
		{description: "byte to string", inputValue: []byte("bytevalue"), expectedOutput: "bytevalue", expectedType: "string", expectedError: ""},
		{description: "bool to string", inputValue: true, expectedOutput: "true", expectedType: "string", expectedError: ""},
	} {
		t.Run(scenario.description, func(t *testing.T) {

			doc, _ := diddoc.NewBuilder().Subject(scenario.inputValue).Build()
			actualOutput := doc.Subject()

			assert.EqualValues(t, scenario.expectedOutput, actualOutput)
			assert.EqualValues(t, scenario.expectedType, reflect.TypeOf(actualOutput).String())

		})
	}
}

func TestVerificationMethods(t *testing.T) {
	for scenario, fn := range map[string]func(t *testing.T){
		"verificationMethod struct": testVerificationMethodStruct,
		"verificationMethod map":    testVerificationMethodMap,
	} {
		t.Run(scenario, func(t *testing.T) {
			fn(t)
		})
	}
}

func testVerificationMethodStruct(t *testing.T) {
	privKey, _ := jwk.ParseKey([]byte(`{"crv":"P-256","kid":"did:example:123#4d98ef1d2c5947a586b2226b200ade72","kty":"EC","x":"nAyQZC6WAvSqnttlft7YOJrqmJx47t3-6l97XQfAGlU","y":"OWcile-qNKOsmXUsUDdYTwn39lvA_Qiml5gFMGaFraQ"}`))
	pubKey, _ := privKey.PublicKey()

	input := diddoc.VerificationMethod{
		Id:          pubKey.KeyID(),
		Type:        "JsonWebKey2020",
		Controller:  "did:example:123",
		PubicKeyJWK: pubKey,
	}
	expectedOutput := []diddoc.VerificationMethod{input}
	doc, _ := diddoc.NewBuilder().VerificationMethod(input).Build()
	actualOutput := doc.VerificationMethod()

	assert.EqualValues(t, expectedOutput, actualOutput)
	assert.EqualValues(t, "[]diddoc.VerificationMethod", reflect.TypeOf(actualOutput).String())
}

func testVerificationMethodMap(t *testing.T) {
	var pubKey map[string]interface{}
	json.Unmarshal([]byte(`{"crv":"P-256","kid":"did:example:123#4d98ef1d2c5947a586b2226b200ade72","kty":"EC","x":"nAyQZC6WAvSqnttlft7YOJrqmJx47t3-6l97XQfAGlU","y":"OWcile-qNKOsmXUsUDdYTwn39lvA_Qiml5gFMGaFraQ"}`), &pubKey)

	input := map[string]interface{}{
		"id":           "did:example:123#4d98ef1d2c5947a586b2226b200ade72",
		"type":         "JsonWebKey2020",
		"controller":   "did:example:123",
		"publicKeyJwk": pubKey,
	}
	expectedOutput := []diddoc.VerificationMethod{
		{
			Id:          "did:example:123#4d98ef1d2c5947a586b2226b200ade72",
			Type:        "JsonWebKey2020",
			Controller:  "did:example:123",
			PubicKeyJWK: pubKey,
		},
	}
	doc, _ := diddoc.NewBuilder().VerificationMethod(input).Build()
	actualOutput := doc.VerificationMethod()

	assert.EqualValues(t, expectedOutput, actualOutput)
	assert.EqualValues(t, "[]diddoc.VerificationMethod", reflect.TypeOf(actualOutput).String())
}

func TestVerificationRelation(t *testing.T) {
	for scenario, fn := range map[string]func(t *testing.T){
		"verificationRelation": testVerificationRelation,
	} {
		t.Run(scenario, func(t *testing.T) {
			fn(t)
		})
	}
}

func testVerificationRelation(t *testing.T) {
	var pubKey map[string]interface{}
	json.Unmarshal([]byte(`{"crv":"P-256","kid":"did:example:123#4d98ef1d2c5947a586b2226b200ade72","kty":"EC","x":"nAyQZC6WAvSqnttlft7YOJrqmJx47t3-6l97XQfAGlU","y":"OWcile-qNKOsmXUsUDdYTwn39lvA_Qiml5gFMGaFraQ"}`), &pubKey)

	input := []diddoc.VerificationRelation{
		map[string]interface{}{"id": "did:example:123#4d98ef1d2c5947a586b2226b200ade72", "type": "JsonWebKey2020", "controller": "did:example:123", "pubicKeyJWK": pubKey},
		"did:example:123456789abcdefghi#keys-1",
	}
	expectedOutput := input
	doc, _ := diddoc.NewBuilder().AssertionMethod(input).Build()
	actualOutput := doc.AssertionMethod()

	assert.EqualValues(t, expectedOutput, actualOutput)
	assert.EqualValues(t, "[]diddoc.VerificationRelation", reflect.TypeOf(actualOutput).String())
}

func TestService(t *testing.T) {
	for scenario, fn := range map[string]func(t *testing.T){
		"service struct": testServiceStruct,
		"service map":    testServiceMap,
	} {
		t.Run(scenario, func(t *testing.T) {
			fn(t)
		})
	}
}

func testServiceStruct(t *testing.T) {
	input := diddoc.Service{
		Id:              "did:example:123#linked-domain",
		Type:            "LinkedDomains",
		ServiceEndpoint: "https://bar.example.com",
	}
	expectedOutput := []diddoc.Service{input}
	doc, _ := diddoc.NewBuilder().Service(input).Build()
	actualOutput := doc.Services()

	assert.EqualValues(t, expectedOutput, actualOutput)
	assert.EqualValues(t, "[]diddoc.Service", reflect.TypeOf(actualOutput).String())
}

func testServiceMap(t *testing.T) {

	input := map[string]interface{}{
		"id":              "did:example:123#linked-domain",
		"type":            "LinkedDomains",
		"serviceEndpoint": "https://bar.example.com",
	}
	expectedOutput := []diddoc.Service{
		{
			Id:              "did:example:123#linked-domain",
			Type:            "LinkedDomains",
			ServiceEndpoint: "https://bar.example.com",
		},
	}
	doc, _ := diddoc.NewBuilder().Service(input).Build()
	actualOutput := doc.Services()

	assert.EqualValues(t, expectedOutput, actualOutput)
	assert.EqualValues(t, "[]diddoc.Service", reflect.TypeOf(actualOutput).String())
}

func TestCustomProperties(t *testing.T) {
	type errorTestCases struct {
		description   string
		inputValue    interface{}
		expectedType  string
		expectedError string
	}
	for _, scenario := range []errorTestCases{
		{description: "bool", inputValue: true, expectedType: "bool", expectedError: ""},
		{description: "float", inputValue: 3.44, expectedType: "float64", expectedError: ""},
		{description: "map", inputValue: map[string]interface{}{"float": 3.44, "bool": false, "int": 2000}, expectedType: "map[string]interface {}", expectedError: ""},
	} {
		t.Run(scenario.description, func(t *testing.T) {

			doc, _ := diddoc.NewBuilder().CustomProperty("test", scenario.inputValue).Build()
			actualOutput := doc.Get("test")

			assert.EqualValues(t, scenario.inputValue, actualOutput)
			assert.EqualValues(t, scenario.expectedType, reflect.TypeOf(actualOutput).String())
		})
	}
}
