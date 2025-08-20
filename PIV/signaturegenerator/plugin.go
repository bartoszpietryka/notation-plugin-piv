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
	"encoding/pem"
	"reflect"

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
	fmt.Println("ss1")
	// use JWT package to sign raw signature.
	method := jwt.GetSigningMethod(jwtAlg)
	fmt.Println("ss2")
	sig, err := method.Sign(payload, privateKey)
	if err != nil {
		return nil, err
	}
	fmt.Println("ss3")
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
		return "", plugin.NewGenericError("Unable to open PIV devices interface" + err.Error())
	}

	if len(pivDevicesNames) == 0 {
		return "", plugin.NewGenericError("No PIV devices found")
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

func GetPrivateKeyInterfaceFromPIVDevice() (crypto.PrivateKey, error) {
	fmt.Println("bb1")
	pivDeviceName, err := GetPIVDeviceName()
	if err != nil {
		return nil, err
	}
	fmt.Println(pivDeviceName)

	pivDevice, err := piv.Open(pivDeviceName)
	if err != nil {
		return nil, plugin.NewGenericError("Unable to use PIV device. " + err.Error())
	}
	fmt.Println("bb3")

	publicCertificate, err := GetPublicCertFromPIVDevice(pivDevice)
	if err != nil {
		return nil, err
	}
	fmt.Println(publicCertificate.PublicKey)
	fmt.Println("bb4")
	pubKey := publicCertificate.PublicKey
	pub, ok2 := pubKey.(*rsa.PublicKey)
	if !ok2 {
		fmt.Println("public key is not an rsa key")
	}
	fmt.Println(pub)
	fmt.Println("bb44")
	auth := piv.KeyAuth{PIN: "234567"}
	privateKey, err := pivDevice.PrivateKey(piv.SlotSignature, publicCertificate.PublicKey, auth)
	if err != nil {
		return nil, plugin.NewGenericError("Unable to use PIV device private key. " + err.Error())
	}
	fmt.Println("bb5")
	_, ok := privateKey.(crypto.Signer)
	if !ok {
		plugin.NewGenericError("Private key didn't implement crypto.Signer")
	}

	fmt.Println("bb10")
	return privateKey, nil
}

func (p *PIVPlugin) GenerateSignature(_ context.Context, req *plugin.GenerateSignatureRequest) (*plugin.GenerateSignatureResponse, error) {
	certs, err := x509core.ReadCertificateFile("./test/example_certs/code_signing.crt")
	check(err)
	fmt.Println("start")

	var privateKeyInterface crypto.PrivateKey
	privateKeyInterface, err = GetPrivateKeyInterfaceFromPIVDevice()
	fmt.Println("PIv device")

	check(err)
	data := sha512.Sum384([]byte(req.Payload))
	rawsignaturepiv, err := privateKeyInterface.(crypto.Signer).Sign(rand.Reader, data[:], crypto.SHA384)

	fmt.Println("sign with PIV")
	fmt.Println(base64.StdEncoding.EncodeToString(rawsignaturepiv))
	check(err)

	privateKey, err := x509core.ReadPrivateKeyFile("./test/example_certs/code_signing.key")
	fmt.Println("Read private key from file")
	check(err)

	rawsignaturefile, err := privateKey.(crypto.Signer).Sign(rand.Reader, data[:], crypto.SHA384)

	fmt.Println("sign with file")
	fmt.Println(base64.StdEncoding.EncodeToString(rawsignaturefile))
	check(err)

	rawsignature, err := sign(string(req.Payload), privateKey, signature.AlgorithmPS384)
	fmt.Println("sign with JWT")
	fmt.Println(base64.StdEncoding.EncodeToString(rawsignature))
	fmt.Println("sign with JWT out")
	check(err)

	//rawsignaturePivJWT, err := sign(string(req.Payload), privateKeyInterface, signature.AlgorithmPS384)
	//fmt.Println("sign with JWT Piv")
	//fmt.Println(base64.StdEncoding.EncodeToString(rawsignaturePivJWT))
	//fmt.Println("sign with JWT out Piv")

	if _, ok := privateKey.(*rsa.PrivateKey); !ok {
		fmt.Println(fmt.Errorf("invalid key type: %s", reflect.TypeOf(privateKey)))
	}

	var Options rsa.PSSOptions
	Options.SaltLength = rsa.PSSSaltLengthEqualsHash

	rawsignaturePSS, err := rsa.SignPSS(rand.Reader, privateKey.(*rsa.PrivateKey), crypto.SHA384, data[:], &Options)
	fmt.Println("sign with JWT PSS")
	fmt.Println(base64.StdEncoding.EncodeToString(rawsignaturePSS))
	fmt.Println("sign with JWT out PSS")
	check(err)

	fmt.Println("verify with PSS")

	var VerifyOptions rsa.PSSOptions
	VerifyOptions.SaltLength = rsa.PSSSaltLengthAuto
	// Read the public key file
	publicKeyBytes, err := os.ReadFile("./test/example_certs/code_signing.pub")
	if err != nil {
		fmt.Println(fmt.Errorf("failed to load public key: %s", err))
	}

	// Decode the public key into a "block"
	publicBlock, _ := pem.Decode(publicKeyBytes)
	if publicBlock == nil || publicBlock.Type != "PUBLIC KEY" {
		fmt.Println(fmt.Errorf("failed to decode PEM block containing public key"))
	}

	// Parse the public key
	publicKey, err := x509.ParsePKIXPublicKey(publicBlock.Bytes)
	if err != nil {
		fmt.Println(fmt.Errorf("parse cert: %s", err))
	}

	// Check the type of the key
	if _, ok := publicKey.(*rsa.PublicKey); !ok {
		fmt.Println(fmt.Errorf("invalid key type: %s", reflect.TypeOf(publicKey)))
	}

	err = rsa.VerifyPSS(publicKey.(*rsa.PublicKey), crypto.SHA384, data[:], rawsignaturePSS, &VerifyOptions)
	if err != nil {
		fmt.Println(fmt.Errorf("invalid signature: %s", err))
	} else {
		fmt.Printf("Signature valid!\n")
	}
	check(err)

	fmt.Println("verify with JWT PSS ")
	err = rsa.VerifyPSS(publicKey.(*rsa.PublicKey), crypto.SHA384, data[:], rawsignature, &VerifyOptions)
	if err != nil {
		fmt.Println(fmt.Errorf("invalid signature: %s", err))
	} else {
		fmt.Printf("Signature valid!\n")
	}
	check(err)

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
