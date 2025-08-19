// Copyright The Notary Project Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"

	"github.com/bartoszpietryka/notation-plugin-piv/plugin"
	"github.com/golang-jwt/jwt"
	"github.com/notaryproject/notation-core-go/signature"
	x509core "github.com/notaryproject/notation-core-go/x509"

	"fmt"
	"os"
)

const Name = "pl.bpietryka.piv.notation.plugin"
const Version = "1.0.0"

var (
	ps256 = jwt.SigningMethodPS256.Name
	ps384 = jwt.SigningMethodPS384.Name
	ps512 = jwt.SigningMethodPS512.Name
	es256 = jwt.SigningMethodES256.Name
	es384 = jwt.SigningMethodES384.Name
	es512 = jwt.SigningMethodES512.Name
)
var signatureAlgJWSAlgMap = map[signature.Algorithm]string{
	signature.AlgorithmPS256: ps256,
	signature.AlgorithmPS384: ps384,
	signature.AlgorithmPS512: ps512,
	signature.AlgorithmES256: es256,
	signature.AlgorithmES384: es384,
	signature.AlgorithmES512: es512,
}

type PIVPlugin struct {
}

func NewPIVPlugin() (*PIVPlugin, error) {
	return &PIVPlugin{}, nil
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func (p *PIVPlugin) DescribeKey(_ context.Context, req *plugin.DescribeKeyRequest) (*plugin.DescribeKeyResponse, error) {
	fmt.Printf("DescribeKey %s", req.KeyID)
	dat, err := os.ReadFile(req.KeyID)
	check(err)
	fmt.Print(string(dat))

	return &plugin.DescribeKeyResponse{
		KeyID:   req.KeyID,
		KeySpec: plugin.KeySpecRSA2048,
	}, nil
}

func sign(payload string, privateKey crypto.PrivateKey, algorithm signature.Algorithm) ([]byte, error) {
	jwtAlg, err := toJWTAlgorithm(algorithm)
	if err != nil {
		return nil, err
	}

	// use JWT package to sign raw signature.
	method := jwt.GetSigningMethod(jwtAlg)
	sig, err := method.Sign(payload, privateKey)
	if err != nil {
		return nil, err
	}

	return base64.RawURLEncoding.DecodeString(sig)
}

func toJWTAlgorithm(alg signature.Algorithm) (string, error) {
	// converts the signature.Algorithm to be jwt package defined
	// algorithm name.
	jwsAlg, ok := signatureAlgJWSAlgMap[alg]
	if !ok {
		return "", &signature.UnsupportedSignatureAlgoError{
			Alg: fmt.Sprintf("#%d", alg)}
	}
	return jwsAlg, nil
}

func toRawCerts(certs []*x509.Certificate) [][]byte {
	var rawCerts [][]byte
	for _, cert := range certs {
		rawCerts = append(rawCerts, cert.Raw)
	}
	return rawCerts
}

func (p *PIVPlugin) GenerateSignature(_ context.Context, req *plugin.GenerateSignatureRequest) (*plugin.GenerateSignatureResponse, error) {
	certs, err := x509core.ReadCertificateFile("./test/example_certs/code_signing.crt")
	check(err)
	fmt.Println("bb")

	privateKey, err := x509core.ReadPrivateKeyFile("./test/example_certs/code_signing.key")
	check(err)

	rawsignature, err := sign(string(req.Payload), privateKey, signature.AlgorithmPS384)

	return &plugin.GenerateSignatureResponse{
		KeyID:            req.KeyID,
		Signature:        rawsignature,
		SigningAlgorithm: plugin.SignatureAlgorithmRSASSA_PSS_SHA384,
		CertificateChain: toRawCerts(certs),
	}, nil
}

func (p *PIVPlugin) GenerateEnvelope(_ context.Context, _ *plugin.GenerateEnvelopeRequest) (*plugin.GenerateEnvelopeResponse, error) {
	return nil, plugin.NewUnsupportedError("GenerateEnvelope operation is not implemented by " + Name + " plugin")
}

func (p *PIVPlugin) VerifySignature(_ context.Context, req *plugin.VerifySignatureRequest) (*plugin.VerifySignatureResponse, error) {
	return nil, plugin.NewUnsupportedError("VerifySignature operation is not implemented by " + Name + " plugin")
}

func (p *PIVPlugin) GetMetadata(_ context.Context, _ *plugin.GetMetadataRequest) (*plugin.GetMetadataResponse, error) {
	return &plugin.GetMetadataResponse{
		SupportedContractVersions: []string{plugin.ContractVersion},
		Name:                      Name,
		Description:               "PIV Plugin for Notation",
		URL:                       "https://github.com/bartoszpietryka/notation-plugin-piv",
		Version:                   Version,
		Capabilities: []plugin.Capability{
			plugin.CapabilitySignatureGenerator},
	}, nil
}
