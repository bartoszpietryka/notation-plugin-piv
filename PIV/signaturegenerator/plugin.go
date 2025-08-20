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
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"

	"github.com/bartoszpietryka/notation-plugin-piv/internal/logger"
	"github.com/bartoszpietryka/notation-plugin-piv/plugin"
	"github.com/go-piv/piv-go/v2/piv"
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

func GetPIVDeviceName() (string, error) {
	pivDevicesNames, err := piv.Cards()

	if err != nil {
		return "", plugin.NewAccessDeniedError("Unable to open PIV devices interface" + err.Error())
	}

	if len(pivDevicesNames) == 0 {
		return "", plugin.NewAccessDeniedError("No PIV devices found")
	}

	if len(pivDevicesNames) > 1 {
		return "", plugin.NewGenericError("Multiple PIV devices found")
	}

	return pivDevicesNames[0], nil
}

func GetPublicCertFromPIVDevice(pivDevice *piv.YubiKey) (*x509.Certificate, error) {

	cert, err := pivDevice.Certificate(piv.SlotSignature)
	if err != nil {
		return nil, plugin.NewGenericError("Unable to get Public Certificate from PIV Device slot 9c. " + err.Error())
	}
	return cert, nil
}

func GetPrivateKeyInterfaceFromPIVDevice(ctx context.Context) (crypto.PrivateKey, error) {
	log := logger.GetLogger(ctx)
	log.Debug("Try to get first PIV device name")
	pivDeviceName, err := GetPIVDeviceName()
	if err != nil {
		return nil, err
	}
	log.Debugf("PIV device name: %s", pivDeviceName)

	log.Debug("Try to open device with PIV interface")
	pivDevice, err := piv.Open(pivDeviceName)
	if err != nil {
		return nil, plugin.NewAccessDeniedError("Unable to use PIV device. " + err.Error())
	}
	log.Debug("Sucessfuly open PIV device")

	log.Debug("Extract public certificate from slot 9c")
	publicCertificate, err := GetPublicCertFromPIVDevice(pivDevice)
	if err != nil {
		return nil, err
	}
	log.Debugf("Public cert Subject: %s  ", publicCertificate.Subject)

	pubKey := publicCertificate.PublicKey
	_, isRSAKey := pubKey.(*rsa.PublicKey)
	if !isRSAKey {
		plugin.NewGenericError("Public key is not an rsa key. Only RSA keys are supported by this plugin")
	}
	//ToDo
	auth := piv.KeyAuth{PIN: "234567"}
	log.Debug("Create signer from slot 9c")
	privateKey, err := pivDevice.PrivateKey(piv.SlotSignature, publicCertificate.PublicKey, auth)
	if err != nil {
		return nil, plugin.NewAccessDeniedError("Unable to use PIV device private key. " + err.Error())
	}

	_, ok := privateKey.(crypto.Signer)
	if !ok {
		plugin.NewAccessDeniedError("Private key don't implement crypto.Signer")
	}

	log.Debug("Good signer from slot 9c")
	return privateKey, nil
}

func GetPrivateKeyInterfaceFromFile(ctx context.Context, path string) (crypto.PrivateKey, error) {
	log := logger.GetLogger(ctx)
	log.Debugf("Try to read Private Key file %s", path)
	privateCertificate, err := x509core.ReadCertificateFile(path)
	if err != nil {
		return nil, plugin.NewGenericErrorf("Unable to get Public Certificate from file. %s %s  ", path, err.Error())
	}
	log.Debug("Private Key file open")

	return privateCertificate, nil
}

func SignWithRSAPSS(ctx context.Context, privateKeyInterface crypto.PrivateKey, digest []byte) ([]byte, error) {
	log := logger.GetLogger(ctx)
	log.Debug("Try to sign RSASSA-PSS with SHA-384")

	options := &rsa.PSSOptions{Hash: crypto.SHA384, SaltLength: rsa.PSSSaltLengthEqualsHash}
	data := sha512.Sum384([]byte(digest))

	rawsignaturePSS, err := privateKeyInterface.(crypto.Signer).Sign(rand.Reader, data[:], options)
	if err != nil {
		return nil, plugin.NewGenericErrorf("Signing failed  %s", err.Error())
	}
	log.Debug("Sucesfully signed with RSASSA-PSS with SHA-384")
	log.Debug("Singanture as base64:")
	log.Debug(base64.StdEncoding.EncodeToString(rawsignaturePSS))

	return rawsignaturePSS, nil
}

func (p *PIVPlugin) GenerateSignature(ctx context.Context, req *plugin.GenerateSignatureRequest) (*plugin.GenerateSignatureResponse, error) {
	log := logger.GetLogger(ctx)
	useFile := false
	var err error
	var privateKeyInterface crypto.PrivateKey
	if useFile {
		privateKeyInterface, err = GetPrivateKeyInterfaceFromFile(ctx, "./test/example_certs/code_signing.crt")
		log.Debug("Private Key ready from file to use")
	} else {
		privateKeyInterface, err = GetPrivateKeyInterfaceFromPIVDevice(ctx)
		log.Debug("PIV device ready to use")
	}
	if err != nil {
		return nil, err
	}

	rawsignature, err := SignWithRSAPSS(ctx, privateKeyInterface, req.Payload)
	if err != nil {
		return nil, err
	}
	//todo
	certs, err := x509core.ReadCertificateFile("./test/example_certs/code_signing.crt")

	return &plugin.GenerateSignatureResponse{
		KeyID:            req.KeyID,
		Signature:        rawsignature,
		SigningAlgorithm: plugin.SignatureAlgorithmRSASSA_PSS_SHA384,
		CertificateChain: toRawCerts(certs),
	}, err
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
