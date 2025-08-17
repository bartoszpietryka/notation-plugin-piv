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

	"github.com/bartoszpietryka/notation-plugin-piv/plugin"
)

const Name = "com.bp.piv.notation.plugin"

type PIVPlugin struct {
}

func NewPIVPlugin() (*PIVPlugin, error) {
	return &PIVPlugin{}, nil
}

func (p *PIVPlugin) DescribeKey(_ context.Context, req *plugin.DescribeKeyRequest) (*plugin.DescribeKeyResponse, error) {
	return &plugin.DescribeKeyResponse{
		KeyID:   req.KeyID,
		KeySpec: plugin.KeySpecRSA3072,
	}, nil
}

func (p *PIVPlugin) GenerateSignature(_ context.Context, req *plugin.GenerateSignatureRequest) (*plugin.GenerateSignatureResponse, error) {
	return &plugin.GenerateSignatureResponse{
		KeyID:            req.KeyID,
		Signature:        []byte("generatedMockSignature"),
		SigningAlgorithm: plugin.SignatureAlgorithmRSASSA_PSS_SHA384,
		CertificateChain: [][]byte{[]byte("mockCert1"), []byte("mockCert2")},
	}, nil
}

func (p *PIVPlugin) GenerateEnvelope(_ context.Context, _ *plugin.GenerateEnvelopeRequest) (*plugin.GenerateEnvelopeResponse, error) {
	return nil, plugin.NewUnsupportedError("GenerateSignature operation is not implemented by " + Name + " plugin")
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
		Version:                   "1.0.0",
		Capabilities: []plugin.Capability{
			plugin.CapabilitySignatureGenerator},
	}, nil
}
