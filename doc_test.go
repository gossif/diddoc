// Copyright 2023 The Go SSI Framework Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package diddoc_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/gossif/diddoc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMarshalDocument(t *testing.T) {
	for scenario, fn := range map[string]func(t *testing.T){
		"unmarshal": testUnmarshal,
		"marshal":   testMarshal,
	} {
		t.Run(scenario, func(t *testing.T) {
			fn(t)
		})
	}
}

func testUnmarshal(t *testing.T) {
	expectedBytes := []byte(`{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/suites/ed25519-2020/v1"],"assertionMethod":[{"controller":"did:example:123","id":"did:example:123#z6MkiukuAuQAE8ozxvmahnQGzApvtW7KT5XXKfojjwbdEomY","publicKeyMultibase":"z5TVraf9itbKXrRvt2DSS95Gw4vqU3CHAdetoufdcKazA","type":"Ed25519VerificationKey2020"}],"authentication":[{"controller":"did:example:123","id":"did:example:123#z6MkecaLyHuYWkayBDLw5ihndj3T1m6zKTGqau3A51G7RBf3","publicKeyMultibase":"zAKJP3f7BD6W4iWEQ9jwndVTCBq8ua2Utt8EEjJ6Vxsf","type":"Ed25519VerificationKey2020"}],"capabilityDelegation":[{"controller":"did:example:123","id":"did:example:123#z6Mkw94ByR26zMSkNdCUi6FNRsWnc2DFEeDXyBGJ5KTzSWyi","publicKeyMultibase":"zHgo9PAmfeoxHG8Mn2XHXamxnnSwPpkyBHAMNF3VyXJCL","type":"Ed25519VerificationKey2020"}],"capabilityInvocation":[{"controller":"did:example:123","id":"did:example:123#z6MkhdmzFu659ZJ4XKj31vtEDmjvsi5yDZG5L7Caz63oP39k","publicKeyMultibase":"z4BWwfeqdp1obQptLLMvPNgBw48p7og1ie6Hf9p5nTpNN","type":"Ed25519VerificationKey2020"}],"controller":"did:example:123","id":"did:example:456","keyAgreement":[{"controller":"did:example:123","id":"did:example:123#z6MkhdmzFu6594633290c794224f1185955236fa7176eb","publicKeyMultibase":"z4BWwfeqdp1obQptLLMvPNgBw48p7og1ie6Hf9p5nTpNN","type":"Ed25519VerificationKey2020"}],"service":[{"id":"did:example:123#linked-domain","type":"LinkedDomains","serviceEndpoint":"https://bar.example.com"}],"verificationMethod":[{"id":"xyz","type":"EcdsaSecp256k1VerificationKey2019","controller":"did:example:123","publicKeyJwk":{"crv":"secp256k1","kid":"xyz","kty":"EC","x":"F5ZFqah38KdBiRl99LdADUxhum5n1yNFdvv5ngW5K24","y":"SA_fdWHQor_kCQkJETqJ4dwLENWY4ArOTEhd8R6nMVw"}}]}`)
	expectedContext := []string{"https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/ed25519-2020/v1"}
	expectedId := "did:example:456"
	expectedControllerIdentifier := []string{"did:example:123"}

	doc := diddoc.NewDocument()
	err := json.Unmarshal(expectedBytes, doc)
	require.NoError(t, err)
	assert.Equal(t, expectedContext, doc.Context())
	assert.Equal(t, expectedId, doc.Subject())
	assert.Equal(t, expectedControllerIdentifier, doc.Controller())
}

func testMarshal(t *testing.T) {
	expectedBytes := []byte(`{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/suites/ed25519-2020/v1"],"assertionMethod":[{"controller":"did:example:123","id":"did:example:123#z6MkiukuAuQAE8ozxvmahnQGzApvtW7KT5XXKfojjwbdEomY","publicKeyMultibase":"z5TVraf9itbKXrRvt2DSS95Gw4vqU3CHAdetoufdcKazA","type":"Ed25519VerificationKey2020"}],"authentication":[{"controller":"did:example:123","id":"did:example:123#z6MkecaLyHuYWkayBDLw5ihndj3T1m6zKTGqau3A51G7RBf3","publicKeyMultibase":"zAKJP3f7BD6W4iWEQ9jwndVTCBq8ua2Utt8EEjJ6Vxsf","type":"Ed25519VerificationKey2020"}],"capabilityDelegation":[{"controller":"did:example:123","id":"did:example:123#z6Mkw94ByR26zMSkNdCUi6FNRsWnc2DFEeDXyBGJ5KTzSWyi","publicKeyMultibase":"zHgo9PAmfeoxHG8Mn2XHXamxnnSwPpkyBHAMNF3VyXJCL","type":"Ed25519VerificationKey2020"}],"capabilityInvocation":[{"controller":"did:example:123","id":"did:example:123#z6MkhdmzFu659ZJ4XKj31vtEDmjvsi5yDZG5L7Caz63oP39k","publicKeyMultibase":"z4BWwfeqdp1obQptLLMvPNgBw48p7og1ie6Hf9p5nTpNN","type":"Ed25519VerificationKey2020"}],"controller":"did:example:123","id":"did:example:456","keyAgreement":[{"controller":"did:example:123","id":"did:example:123#z6MkhdmzFu6594633290c794224f1185955236fa7176eb","publicKeyMultibase":"z4BWwfeqdp1obQptLLMvPNgBw48p7og1ie6Hf9p5nTpNN","type":"Ed25519VerificationKey2020"}],"service":[{"id":"did:example:123#linked-domain","type":"LinkedDomains","serviceEndpoint":"https://bar.example.com"}],"verificationMethod":[{"id":"xyz","type":"EcdsaSecp256k1VerificationKey2019","controller":"did:example:123","publicKeyJwk":{"crv":"secp256k1","kid":"xyz","kty":"EC","x":"F5ZFqah38KdBiRl99LdADUxhum5n1yNFdvv5ngW5K24","y":"SA_fdWHQor_kCQkJETqJ4dwLENWY4ArOTEhd8R6nMVw"}}]}`)

	doc := diddoc.NewDocument()
	require.NoError(t, json.Unmarshal(expectedBytes, doc))

	actualBytes, err := json.Marshal(doc)
	require.NoError(t, err)

	assert.True(t, reflect.DeepEqual(expectedBytes, actualBytes))
}

func TestGetAssociatedVerificationMethod(t *testing.T) {
	for scenario, fn := range map[string]func(t *testing.T){
		"found":     tstVerificationRelationFound,
		"not found": tstVerificationRelationNotFound,
		"embedded":  tstVerificationRelationWithEmbedded,
	} {
		t.Run(scenario, func(t *testing.T) {
			fn(t)
		})
	}
}

func tstVerificationRelationFound(t *testing.T) {
	inputBytes := []byte(`{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/suites/ed25519-2020/v1"],"assertionMethod":[{"controller":"did:example:123","id":"did:example:123#z6MkiukuAuQAE8ozxvmahnQGzApvtW7KT5XXKfojjwbdEomY","publicKeyMultibase":"z5TVraf9itbKXrRvt2DSS95Gw4vqU3CHAdetoufdcKazA","type":"Ed25519VerificationKey2020"}],"authentication":[{"controller":"did:example:123","id":"did:example:123#z6MkecaLyHuYWkayBDLw5ihndj3T1m6zKTGqau3A51G7RBf3","publicKeyMultibase":"zAKJP3f7BD6W4iWEQ9jwndVTCBq8ua2Utt8EEjJ6Vxsf","type":"Ed25519VerificationKey2020"}],"capabilityDelegation":[{"controller":"did:example:123","id":"did:example:123#z6Mkw94ByR26zMSkNdCUi6FNRsWnc2DFEeDXyBGJ5KTzSWyi","publicKeyMultibase":"zHgo9PAmfeoxHG8Mn2XHXamxnnSwPpkyBHAMNF3VyXJCL","type":"Ed25519VerificationKey2020"}],"capabilityInvocation":[{"controller":"did:example:123","id":"did:example:123#z6MkhdmzFu659ZJ4XKj31vtEDmjvsi5yDZG5L7Caz63oP39k","publicKeyMultibase":"z4BWwfeqdp1obQptLLMvPNgBw48p7og1ie6Hf9p5nTpNN","type":"Ed25519VerificationKey2020"}],"controller":"did:example:123","id":"did:example:456","keyAgreement":[{"controller":"did:example:123","id":"did:example:123#z6MkhdmzFu6594633290c794224f1185955236fa7176eb","publicKeyMultibase":"z4BWwfeqdp1obQptLLMvPNgBw48p7og1ie6Hf9p5nTpNN","type":"Ed25519VerificationKey2020"}],"service":[{"id":"did:example:123#linked-domain","type":"LinkedDomains","serviceEndpoint":"https://bar.example.com"}],"verificationMethod":[{"id":"xyz","type":"EcdsaSecp256k1VerificationKey2019","controller":"did:example:123","publicKeyJwk":{"crv":"secp256k1","kid":"xyz","kty":"EC","x":"F5ZFqah38KdBiRl99LdADUxhum5n1yNFdvv5ngW5K24","y":"SA_fdWHQor_kCQkJETqJ4dwLENWY4ArOTEhd8R6nMVw"}}]}`)

	doc := diddoc.NewDocument()
	require.NoError(t, json.Unmarshal(inputBytes, doc))

	expectedOutput := []diddoc.VerificationMethod{
		{
			Controller:         "did:example:123",
			Id:                 "did:example:123#z6MkiukuAuQAE8ozxvmahnQGzApvtW7KT5XXKfojjwbdEomY",
			PublicKeyMultibase: "z5TVraf9itbKXrRvt2DSS95Gw4vqU3CHAdetoufdcKazA",
			Type:               "Ed25519VerificationKey2020",
		},
	}

	actualVerificationMethods, err := doc.GetAssociatedVerificationMethod(diddoc.AssertionMethod)
	assert.NoError(t, err)
	assert.True(t, reflect.DeepEqual(actualVerificationMethods, expectedOutput))
}

func tstVerificationRelationNotFound(t *testing.T) {
	inputBytes := []byte(`{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/suites/ed25519-2020/v1"],"authentication":[{"controller":"did:example:123","id":"did:example:123#z6MkecaLyHuYWkayBDLw5ihndj3T1m6zKTGqau3A51G7RBf3","publicKeyMultibase":"zAKJP3f7BD6W4iWEQ9jwndVTCBq8ua2Utt8EEjJ6Vxsf","type":"Ed25519VerificationKey2020"}],"capabilityDelegation":[{"controller":"did:example:123","id":"did:example:123#z6Mkw94ByR26zMSkNdCUi6FNRsWnc2DFEeDXyBGJ5KTzSWyi","publicKeyMultibase":"zHgo9PAmfeoxHG8Mn2XHXamxnnSwPpkyBHAMNF3VyXJCL","type":"Ed25519VerificationKey2020"}],"capabilityInvocation":[{"controller":"did:example:123","id":"did:example:123#z6MkhdmzFu659ZJ4XKj31vtEDmjvsi5yDZG5L7Caz63oP39k","publicKeyMultibase":"z4BWwfeqdp1obQptLLMvPNgBw48p7og1ie6Hf9p5nTpNN","type":"Ed25519VerificationKey2020"}],"controller":"did:example:123","id":"did:example:456","keyAgreement":[{"controller":"did:example:123","id":"did:example:123#z6MkhdmzFu6594633290c794224f1185955236fa7176eb","publicKeyMultibase":"z4BWwfeqdp1obQptLLMvPNgBw48p7og1ie6Hf9p5nTpNN","type":"Ed25519VerificationKey2020"}],"service":[{"id":"did:example:123#linked-domain","type":"LinkedDomains","serviceEndpoint":"https://bar.example.com"}],"verificationMethod":[{"id":"xyz","type":"EcdsaSecp256k1VerificationKey2019","controller":"did:example:123","publicKeyJwk":{"crv":"secp256k1","kid":"xyz","kty":"EC","x":"F5ZFqah38KdBiRl99LdADUxhum5n1yNFdvv5ngW5K24","y":"SA_fdWHQor_kCQkJETqJ4dwLENWY4ArOTEhd8R6nMVw"}}]}`)

	doc := diddoc.NewDocument()
	require.NoError(t, json.Unmarshal(inputBytes, doc))

	expectedOutput := []diddoc.VerificationMethod{}

	actualVerificationMethods, err := doc.GetAssociatedVerificationMethod(diddoc.AssertionMethod)
	assert.ErrorContains(t, err, "not_found")
	assert.True(t, reflect.DeepEqual(actualVerificationMethods, expectedOutput))
}

func tstVerificationRelationWithEmbedded(t *testing.T) {
	inputBytes := []byte(`{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/suites/jws-2020/v1"],"id": "did:example:123456789abcdefghi","verificationMethod":[{"id":"did:example:123#key-0","type":"JsonWebKey2020","controller":"did:example:123","publicKeyJwk": {"kty":"OKP","crv":"Ed25519","x": "VCpo2LMLhn6iWku8MKvSLg2ZAoC-nlOyPVQaO3FxVeQ"}},{"id":"did:example:123#key-1","type":"JsonWebKey2020","controller":"did:example:123","publicKeyJwk": {"kty":"OKP","crv":"X25519","x":"pE_mG098rdQjY3MKK2D5SUQ6ZOEW3a6Z6T7Z4SgnzCE"}}],"authentication":["did:example:123#key-1",{"id":"did:example:123456789abcdefghi#keys-2","type":"Ed25519VerificationKey2020","controller":"did:example:123456789abcdefghi","publicKeyMultibase":"zH3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"}]}`)

	doc := diddoc.NewDocument()
	require.NoError(t, json.Unmarshal(inputBytes, doc))

	expectedOutput := []diddoc.VerificationMethod{
		{
			Controller: "did:example:123",
			Id:         "did:example:123#key-1",
			Type:       "JsonWebKey2020",
			PubicKeyJWK: map[string]interface{}{
				"kty": "OKP",
				"crv": "X25519",
				"x":   "pE_mG098rdQjY3MKK2D5SUQ6ZOEW3a6Z6T7Z4SgnzCE",
			},
		},
		{
			Controller:         "did:example:123456789abcdefghi",
			Id:                 "did:example:123456789abcdefghi#keys-2",
			PublicKeyMultibase: "zH3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV",
			Type:               "Ed25519VerificationKey2020",
		},
	}

	actualVerificationMethods, err := doc.GetAssociatedVerificationMethod(diddoc.Authentication)

	assert.NoError(t, err)
	assert.True(t, reflect.DeepEqual(actualVerificationMethods, expectedOutput))

}

func TestGetVerificationMethodById(t *testing.T) {
	inputBytes := []byte(`{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/suites/jws-2020/v1"],"id": "did:example:123456789abcdefghi","verificationMethod":[{"id":"did:example:123#key-0","type":"JsonWebKey2020","controller":"did:example:123","publicKeyJwk": {"kty":"OKP","crv":"Ed25519","x": "VCpo2LMLhn6iWku8MKvSLg2ZAoC-nlOyPVQaO3FxVeQ"}},{"id":"did:example:123#key-1","type":"JsonWebKey2020","controller":"did:example:123","publicKeyJwk": {"kty":"OKP","crv":"X25519","x":"pE_mG098rdQjY3MKK2D5SUQ6ZOEW3a6Z6T7Z4SgnzCE"}}],"authentication":["did:example:123456789abcdefghi#keys-1",{"id":"did:example:123456789abcdefghi#keys-2","type":"Ed25519VerificationKey2020","controller":"did:example:123456789abcdefghi","publicKeyMultibase":"zH3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"}]}`)

	doc := diddoc.NewDocument()
	require.NoError(t, json.Unmarshal(inputBytes, doc))

	type errorTestCases struct {
		description    string
		input          string
		expectedOutput diddoc.VerificationMethod
		expectedError  string
	}
	for _, scenario := range []errorTestCases{
		{description: "found", input: "did:example:123#key-1",
			expectedOutput: diddoc.VerificationMethod{Controller: "did:example:123", Id: "did:example:123#key-1", Type: "JsonWebKey2020", PubicKeyJWK: map[string]interface{}{"kty": "OKP", "crv": "X25519", "x": "pE_mG098rdQjY3MKK2D5SUQ6ZOEW3a6Z6T7Z4SgnzCE"}}, expectedError: ""},
	} {
		t.Run(scenario.description, func(t *testing.T) {

			actualOutput, err := doc.GetVerificationMethodById(scenario.input)
			if scenario.expectedError == "" {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, scenario.expectedError)
			}
			assert.EqualValues(t, scenario.expectedOutput, actualOutput)

		})
	}
}
