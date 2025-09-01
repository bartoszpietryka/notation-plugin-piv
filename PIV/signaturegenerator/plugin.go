// Copyright Bartosz Pietryka.
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
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"

	"github.com/bartoszpietryka/notation-plugin-piv/internal/logger"
	"github.com/bartoszpietryka/notation-plugin-piv/internal/version"
	"github.com/bartoszpietryka/notation-plugin-piv/plugin"
	"github.com/go-piv/piv-go/v2/piv"
	x509core "github.com/notaryproject/notation-core-go/x509"
)

const Name = "pl.bpietryka.piv.notation.plugin"

type PIVPlugin struct {
}

func NewPIVPlugin() (*PIVPlugin, error) {
	return &PIVPlugin{}, nil
}

func (p *PIVPlugin) DescribeKey(_ context.Context, req *plugin.DescribeKeyRequest) (*plugin.DescribeKeyResponse, error) {
	//toDo add support for other key formats
	return &plugin.DescribeKeyResponse{
		KeyID:   req.KeyID,
		KeySpec: plugin.KeySpecRSA2048,
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
		Version:                   version.GetVersion(),
		Capabilities: []plugin.Capability{
			plugin.CapabilitySignatureGenerator},
	}, nil
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

func GetKeyAndLeafCertFromPIVDevice(ctx context.Context, pin string) (crypto.PrivateKey, *x509.Certificate, error) {
	log := logger.GetLogger(ctx)
	log.Debug("Try to get first PIV device name")
	pivDeviceName, err := GetPIVDeviceName()
	if err != nil {
		return nil, nil, err
	}
	log.Debugf("PIV device name: %s", pivDeviceName)

	log.Debug("Try to open device with PIV interface")
	pivDevice, err := piv.Open(pivDeviceName)
	if err != nil {
		return nil, nil, plugin.NewAccessDeniedError("Unable to use PIV device. " + err.Error())
	}
	log.Debug("Sucessfuly open PIV device")

	log.Debug("Extract public certificate from slot 9c")
	publicCertificate, err := GetPublicCertFromPIVDevice(pivDevice)
	if err != nil {
		return nil, nil, err
	}
	log.Debugf("Public cert Subject: %s  ", publicCertificate.Subject)

	pubKey := publicCertificate.PublicKey
	_, isRSAKey := pubKey.(*rsa.PublicKey)
	if !isRSAKey {
		plugin.NewGenericError("Public key is not an rsa key. Only RSA keys are supported by this plugin")
	}

	auth := piv.KeyAuth{PIN: pin}
	if pin == "" {
		return nil, nil, plugin.NewAccessDeniedError("Empty PIN")
	}
	log.Debug("Create signer from slot 9c")
	privateKey, err := pivDevice.PrivateKey(piv.SlotSignature, publicCertificate.PublicKey, auth)
	if err != nil {
		return nil, nil, plugin.NewAccessDeniedError("Unable to use PIV device private key. " + err.Error())
	}

	_, ok := privateKey.(crypto.Signer)
	if !ok {
		plugin.NewAccessDeniedError("Private key don't implement crypto.Signer")
	}

	log.Debug("Good signer from slot 9c")
	return privateKey, publicCertificate, nil
}

func GetKeyAndCertChainFromPIVDevice(ctx context.Context, pin string, publicCertifcatePath string) (crypto.PrivateKey, []*x509.Certificate, error) {
	log := logger.GetLogger(ctx)
	var privateKeyInterface crypto.PrivateKey
	var publicCertificates []*x509.Certificate

	privateKeyInterface, certificateFromPIV, err := GetKeyAndLeafCertFromPIVDevice(ctx, pin)
	if err != nil {
		return nil, nil, err
	}
	log.Debug("PIV device returned cert and Signer interface")
	if publicCertifcatePath == "" {
		log.Debug("Parameter cert_path not specified. Using certificate extracted from PIV Device as certificate chain")
		if certificateFromPIV == nil {
			return nil, nil, plugin.NewAccessDeniedError("No Public certificate found")
		}
		publicCertificates = append(publicCertificates, certificateFromPIV)
	} else {
		log.Debug("Using certificate chain from pluginConfig cert_path ")
		publicCertificates, err = GetCertChainFromFile(ctx, publicCertifcatePath)
		if err != nil {
			return nil, nil, err
		}
		if !publicCertificates[0].Equal(certificateFromPIV) {
			return nil, nil, plugin.NewAccessDeniedError("Leaf certificate in cert_path does not match certificate stored on PIV device")
		}
	}
	return privateKeyInterface, publicCertificates, nil
}

func GetCertChainFromFile(ctx context.Context, publicCertifcatePath string) ([]*x509.Certificate, error) {
	log := logger.GetLogger(ctx)
	if publicCertifcatePath == "" {
		return nil, plugin.NewGenericErrorf("pluginConfig cert_path not specified")
	}
	log.Debugf("Try to read Public Certifcates file %s", publicCertifcatePath)
	publicCertificates, err := x509core.ReadCertificateFile(publicCertifcatePath)
	if err != nil {
		return nil, plugin.NewGenericErrorf("Unable to get Public Certifcate from file. %s %s  ", publicCertifcatePath, err.Error())
	}
	log.Debug("Public Certifcates file open")
	if len(publicCertificates) == 0 {
		return nil, plugin.NewGenericErrorf("No certifcates found in file. %s", publicCertifcatePath)
	}
	return publicCertificates, nil
}

func GetKeyAndCertChainFromFile(ctx context.Context, privateKeyPath string, publicCertifcatePath string) (crypto.PrivateKey, []*x509.Certificate, error) {
	log := logger.GetLogger(ctx)
	log.Debugf("Try to read Private Key file %s", privateKeyPath)
	if privateKeyPath == "" {
		return nil, nil, plugin.NewGenericErrorf("pluginConfig key_path not specified")
	}
	privateKey, err := x509core.ReadPrivateKeyFile(privateKeyPath)
	if err != nil {
		return nil, nil, plugin.NewGenericErrorf("Unable to get Private Key from file. %s %s  ", privateKeyPath, err.Error())
	}
	log.Debug("Private Key file open")

	var publicCertificates []*x509.Certificate
	publicCertificates, err = GetCertChainFromFile(ctx, publicCertifcatePath)
	if err != nil {
		return nil, nil, err
	}

	return privateKey, publicCertificates, nil
}

func SignWithRSAPSS(ctx context.Context, privateKeyInterface crypto.PrivateKey, digest []byte) ([]byte, error) {
	log := logger.GetLogger(ctx)
	log.Debug("Try to sign RSASSA-PSS with SHA-256")

	options := &rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: rsa.PSSSaltLengthEqualsHash}
	data := sha256.Sum256([]byte(digest))

	rawsignaturePSS, err := privateKeyInterface.(crypto.Signer).Sign(rand.Reader, data[:], options)
	if err != nil {
		return nil, plugin.NewGenericErrorf("Signing failed  %s", err.Error())
	}
	log.Debug("Sucesfully signed with RSASSA-PSS with SHA-256")
	log.Debug("Singanture as base64:")
	log.Debug(base64.StdEncoding.EncodeToString(rawsignaturePSS))

	return rawsignaturePSS, nil
}

func (p *PIVPlugin) GenerateSignature(ctx context.Context, req *plugin.GenerateSignatureRequest) (*plugin.GenerateSignatureResponse, error) {
	log := logger.GetLogger(ctx)

	var err error
	var privateKeyInterface crypto.PrivateKey
	var publicCertificates []*x509.Certificate

	if req.PluginConfig["key_path"] == "" {
		privateKeyInterface, publicCertificates, err = GetKeyAndCertChainFromPIVDevice(ctx, req.PluginConfig["PIN"], req.PluginConfig["cert_path"])
		log.Debug("PIV device ready to use")
	} else {
		privateKeyInterface, publicCertificates, err = GetKeyAndCertChainFromFile(ctx, req.PluginConfig["key_path"], req.PluginConfig["cert_path"])
		log.Debug("Private Key from file ready to use")
	}
	if err != nil {
		return nil, err
	}
	rawsignature, err := SignWithRSAPSS(ctx, privateKeyInterface, req.Payload)
	if err != nil {
		return nil, err
	}
	return &plugin.GenerateSignatureResponse{
		KeyID:            req.KeyID,
		Signature:        rawsignature,
		SigningAlgorithm: plugin.SignatureAlgorithmRSASSA_PSS_SHA256,
		CertificateChain: toRawCerts(publicCertificates),
	}, err
}
