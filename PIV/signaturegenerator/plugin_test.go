// Copyright Bartosz Pietryka.
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
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"
)

const (
	testSelfSignedCertificateText = `-----BEGIN CERTIFICATE-----
MIIDZzCCAk+gAwIBAgIUKBnV5FyKlsfCA9zZpr/GpVWiVNcwDQYJKoZIhvcNAQEL
BQAwQTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAldBMQ8wDQYDVQQKDAZOb3Rhcnkx
FDASBgNVBAMMC3Bpdi1leGFtcGxlMB4XDTI1MDgzMDIwMDY1OVoXDTQ1MDgzMDIw
MDY1OVowQTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAldBMQ8wDQYDVQQKDAZOb3Rh
cnkxFDASBgNVBAMMC3Bpdi1leGFtcGxlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEA2xuj2P4IFtm8LXD5bRAF2hh7iBhfyUWiVniFL6Q8ppWqhQs6e0+E
Yrh5xxWU4iY/2LJDVrJc6+prx860Y9G6UKLwTQw/DmmsboJAQjEeLj3RNQ3C8WiO
Mx6vcfz4DcYDikZ1h6cCkKut4gq/1R1rpZHQoIF/B9qTHfZQpFyxkbo9juRLFHlh
1A7FwUlQ5CnImy26/MW+HOSOQlPdJXjYjg5hKoJKJL5Fhg4iR3B6F/8k7kpv0FeD
bgRm3/77TZsS83WvaF8WDH5pvw9uIyib9IgSpo1vCo4EZXtmBq5iy184U7QVRRsg
+IAfjsp/EfqpUn2qcND6OG8hcLgOGMWp7QIDAQABo1cwVTAOBgNVHQ8BAf8EBAMC
B4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwMwDAYDVR0TAQH/BAIwADAdBgNVHQ4E
FgQU3Bx6zONc6snnQ0ZtYTxdQR+cixMwDQYJKoZIhvcNAQELBQADggEBANlBIDB5
cyMe+MAMnkOnqT4Y9bQQRk/pJxonNF+yq+uMrINHqpGQAXn0ZPoGlV9AQYHSp1yn
H1hoHup35YRf+GA+mxQ5/JDQOsoboLos1yX0PQ+HeryHnwoOMFXmrMh2Vk7HC1lw
Q3H1QtJUeLnkbcrR23X5u8GxGDsvWCtsMrnzApxrTp4hIWf10TKpkztkp3Y3hWgS
MxbnKXeTwDKLk6V09WGhqd3mCuPLGj4NUq8ECdxytG734QWR4Yo+nINvp2DicS5w
YySHjEfZlDgffV3u7XB1w3osE4qqzQOJ+BMN0lgyjfxgM+eBviXDsVqjofvYi9mo
4o3iNBJk+p5R5bQ=
-----END CERTIFICATE-----`
	testSelfSignedCertificateKeyText = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDbG6PY/ggW2bwt
cPltEAXaGHuIGF/JRaJWeIUvpDymlaqFCzp7T4RiuHnHFZTiJj/YskNWslzr6mvH
zrRj0bpQovBNDD8OaaxugkBCMR4uPdE1DcLxaI4zHq9x/PgNxgOKRnWHpwKQq63i
Cr/VHWulkdCggX8H2pMd9lCkXLGRuj2O5EsUeWHUDsXBSVDkKcibLbr8xb4c5I5C
U90leNiODmEqgkokvkWGDiJHcHoX/yTuSm/QV4NuBGbf/vtNmxLzda9oXxYMfmm/
D24jKJv0iBKmjW8KjgRle2YGrmLLXzhTtBVFGyD4gB+Oyn8R+qlSfapw0Po4byFw
uA4YxantAgMBAAECggEAD6yjhQjElWCQLgQF+T+123X4PbKDWl0JPFG03W/3XXIZ
gm5c3v4U72cDtzKbta3yJVNjWSwQqlkudVsb29mLZZddGiCae4fNwRNqULyTdyVk
S6enXtO8UHs30S9n+LxF++Sx0GQp3SWa89pnAhzvsCbam5DdVeIqDMZWhduSYbqk
0WDsRcComLkZOKbWRlQjWH/3W08vhHo6/rqpykXMEIGUNVfXS9o2DwiSSchMpCdY
7BY9sC+tHdlG6LCzrffTk+IEFVTfkQ1IDm0fad15sAIsfGPBigjfyCHk8w8F2q6k
lucLfotu+sajOmUe2Cq8VsFAD/Nd3LNqFhRhievFlQKBgQDw4qJwX5Ye7VPMEVGb
4j6lnTn0aNsiyvStNWmdK2Eaq27HD2SAFqeFa4YvPi9zopFesOrABPylMVqOoXFr
dkpmV5ROq3OxqUDr0pHjtwi+1bY4dwllxX9rhJLN+mszS+y5TX2zIHJYGqjnbOJa
5S35PRAljhdCjmOFTPzYi0EAawKBgQDo2zGxR7h81UYbwWazuW/cBu02gAwpN4XL
e/YIvWC6dw4571ujcuVWxzCQ5ORuRZi+R8H8SfX7AKtCae30F9jhaIVDbulXSXBu
YLIBXjA7nOONow/hRmGfd484tmiqpSa1sGnoU6P8vyyjJ13H5bqDe25+ZSHECZGC
d5Oybtm1BwKBgQCy5Z3+Fv9GuLsjMzmIq94a4UnJWpZkoJZWjPSC5VSYmfkLnULm
XezMCa7+JxDWsEWGLZ4qPYnkpWK7yuqRBKj8mM5sHqktqKWufhQbKjQ0hkNua/lu
u96F20+r6e7zic+lTweroM1K4YHPXe490zbxg4gaXAyqQVVoCmU97S25QQKBgQCK
HiH+jpUObo60PeZGKnMAJpejoRYViJpy1Sddjb8HO0ET+jb331nLPEFBYJNiGSP9
kaCtnc0qwf3TWfPLui1pnk6Vbf84SBZJUk+jYhPn+Co9RABSViXnqcopEIFK3sT0
NhzLsnjtnRPD/sCwpkIYZSloDWKW3joSEg1oZDn8FwKBgGvbip1O/kUv/R3D5r09
vH8UCZHmM2l/sI5LzQbrQpklb104ef+It26nnpm/cHgs7UAMXS5WWjbcHpum9S61
W84MeITigadhcK6btemRpuBsFuzBOE4FOS6LDzuvfP6ChqKsRC3I5WSYaadzc0Pn
P8JYrP8xH3vzCbTkd7PvXW0K
-----END PRIVATE KEY-----`
	testCertificateChainText = `-----BEGIN CERTIFICATE-----
MIIDmDCCAoCgAwIBAgIUVioQuR5L+XXO2xVAXfYzxUa0lWowDQYJKoZIhvcNAQEL
BQAwUTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAldBMQ8wDQYDVQQKDAZOb3Rhcnkx
JDAiBgNVBAMMG3Bpdi1leGFtcGxlLUludGVybWlkaWF0ZS1DQTAeFw0yNTA4MzAy
MDA3NTVaFw00NTA4MzAyMDA3NTVaMEExCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJX
QTEPMA0GA1UECgwGTm90YXJ5MRQwEgYDVQQDDAtwaXYtZXhhbXBsZTCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAM0mAwcuMmLo/vG1AK/ny8mCWQLO3HCP
6QyXiLIarY08gNg/ZAAvH9kwh/UirYL5tMdsTrbYueO4FdGQv1ld3Z4eB+K52Fze
DfrAFpEMKaBh+unGIpM83gFrZPYBB/oQgIddGvEWFE3IPNy2DDgrIggTd50lsU3R
Eizho+WKNMSAId2b6JhkpVoe44DJRktI1PYVRtTbq9c2dJl3exof37w+Wh/gXBw+
yiYmpCau3MhgbMOj9LmqVwgc2Bk92NcxaKezKqvoH47usOWLzPTPLUGjGWAagb+g
Lqnju//UVa5hYHYoNI2lu2yMRnWNY6rHFGVBi6Y32iEAhYRNHoe7bS0CAwEAAaN4
MHYwDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMDMAwGA1Ud
EwEB/wQCMAAwHQYDVR0OBBYEFBbr3aWZ+MO6OwXBkuaF8g5DABwJMB8GA1UdIwQY
MBaAFFBci48mbdUPg7RgNk3XnsZyPizJMA0GCSqGSIb3DQEBCwUAA4IBAQAWuVMc
21wM9S92c9+T563AQ8NsR99n7ICrl3MfMXzgZpII2Osd7pR6/Jnu7k4oP9umOMUk
ADyXSrHbyKR/nPS4TJO9QQ4z/vVv7BYf43FvtpiViT1WsTl80kkIup2OGhp2rxid
0Q8QxUYGqkxMkvbsOBJOLFAMCrZK0ZD+VPxah6TYebtAZzyEpVlE3VC74SLc/vP+
qANrD1FAH7YOa39jF2KTmLH6NhTbbaXxhcD2dSmv/UdMa3l4YgvejHEuqdQRUchZ
n0zYuaDmyv1ZZ00LH/HXWRkUEYF2P6NtfeK34Ksg6m8JNSx0x3UowrsmVTvLYQOL
hqKeNqLtOitn2NVp
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDizCCAnOgAwIBAgIUVu381j+cRH17D2SiiDvD4CmtDnUwDQYJKoZIhvcNAQEL
BQAwSTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAldBMQ8wDQYDVQQKDAZOb3Rhcnkx
HDAaBgNVBAMME3Bpdi1leGFtcGxlLVJvb3QtQ0EwHhcNMjUwODMwMjAwNzQ3WhcN
NDUwODMwMjAwNzQ3WjBRMQswCQYDVQQGEwJVUzELMAkGA1UECAwCV0ExDzANBgNV
BAoMBk5vdGFyeTEkMCIGA1UEAwwbcGl2LWV4YW1wbGUtSW50ZXJtaWRpYXRlLUNB
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq9Zlf5EA4K17alcorMIP
wHHKjdBWEnnNfUYt+cTRk3vNmaKH6xJ7EYtHta5jcL1Q9mkWakyFfrGeaVFxuxk8
PpQ241S0zgjLi2QSg22SVKLAlSodA+6LOp5KSVpIkl52/O5JnJVeFlnqCPBMoKrU
EW1ywro9FFdcKGAtpz5LxUaWHR3z+fvpLFrmlzZhpE9H57Itl0k551EdudF46LBR
CO/8dhR2C4+1cUCOpN+JM0N/hUHK19ss9WDVge3lBBpsE3+lHso4cxutpr9/RN3G
o3YaoaNATpSkuKUDwTgTdVX/U6iIo6XsM/+y2rrS2tsSh+ZF2XNZLYtO7EIJETpv
HQIDAQABo2MwYTAdBgNVHQ4EFgQUUFyLjyZt1Q+DtGA2TdeexnI+LMkwHwYDVR0j
BBgwFoAU/Yc7k5TaujECZLTzF3eNyW0XEdQwDwYDVR0TAQH/BAUwAwEB/zAOBgNV
HQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBAEz7fp+y6eIn3ehcRYoGx0QQ
Z+pexLQiy2xEXQaVvCNsegA7LJ8oNFH071Om84Wz811rr/iXerbK9F3/hBqj9ZNc
U4p7kiyEcxo/mD59ugkIJM5wmSd/0erYW2Dt+b4naP0r0RZZi1uu1GvnKAUP6DB3
sMSTbGWF6WU0GMd2mdjPDHoJi1ir1mQdK0ZbGPqQF7zljhZJSLXmcTe/GC2UAjdc
k5isfJidHAXSKMLeScuI/n5csMSvNd4qx+1tAy1N2XJFAOH1i5Gqa6rRQkzv/twX
eOfnP2d2mfO8Yzoa6twNXf7RdwKuO9URdm5juoJg3KlLhSCKO9dJShT3bs9RJco=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDgzCCAmugAwIBAgIUdDQUqK+xqv3XuyyUkP1gcDcofzswDQYJKoZIhvcNAQEL
BQAwSTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAldBMQ8wDQYDVQQKDAZOb3Rhcnkx
HDAaBgNVBAMME3Bpdi1leGFtcGxlLVJvb3QtQ0EwHhcNMjUwODMwMjAwNzM1WhcN
NDUwODMwMjAwNzM1WjBJMQswCQYDVQQGEwJVUzELMAkGA1UECAwCV0ExDzANBgNV
BAoMBk5vdGFyeTEcMBoGA1UEAwwTcGl2LWV4YW1wbGUtUm9vdC1DQTCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBALTKNcyaQ/F051FdiKVQ+V2lBFTvQghR
sN6iN3usvYZlLtlWfQoYshyzzLL0KL1SwLidokUoUNrw/7zzPCVT4fwz2OjoHKSr
E+vjk6zflYC7LYzpWxO1fsQHLyFP1sk0FE2bqZZ4J4ThbHq9PIV8qYHdxpN1emxB
5rGjMt//eHHId5AwQZuZcm+lcET6v+8NVDY2DwAM9sK/QR0wOpS75SPcRxGOgAmH
nm635pWhwKl8PJ9BDF1bc+/KisFUV+nCSQXbN29EQHVkdtSUlbjDKG6ksy9v18u8
FyLUgwYz9Tzr6nM8/DhssQmZydjhvoNWwKCL7tGaQvE+EpBZYZ7Es3MCAwEAAaNj
MGEwHQYDVR0OBBYEFP2HO5OU2roxAmS08xd3jcltFxHUMB8GA1UdIwQYMBaAFP2H
O5OU2roxAmS08xd3jcltFxHUMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQD
AgKEMA0GCSqGSIb3DQEBCwUAA4IBAQBPnNu38sl9MkLG2/G8FN1rUxGpXwD3FaIh
5Ko0ml6uJTTGdO3Sg9lpYPx9OOiHUyVkwfzb+JwsM5HZXKFtS3r4ZWkRcO0uUigR
rHORvoTVwTi500lKOKpg8V2y0L76+a3l7W5HfkTn3Z/OcZC+O8HG/503mXjraH6f
xO64mV4yG3MqjO40OFEjL+/cAbipAlVHvf9FhyUDgGSRGapr8TUnrDcOsAzH6rWF
7NbQbOz4sbnyMmI52ZF6sNogxPrPFi+Y3/N3ArMlDWPDRu2bG9tn8acA9OYYlbiK
N0etPxj1H2IncVGEzi+UYTNVqraKndxFL1aexIS6sVjCDh2ynELI
-----END CERTIFICATE-----`
	testCertificateChainKeyText = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDNJgMHLjJi6P7x
tQCv58vJglkCztxwj+kMl4iyGq2NPIDYP2QALx/ZMIf1Iq2C+bTHbE622LnjuBXR
kL9ZXd2eHgfiudhc3g36wBaRDCmgYfrpxiKTPN4Ba2T2AQf6EICHXRrxFhRNyDzc
tgw4KyIIE3edJbFN0RIs4aPlijTEgCHdm+iYZKVaHuOAyUZLSNT2FUbU26vXNnSZ
d3saH9+8Plof4FwcPsomJqQmrtzIYGzDo/S5qlcIHNgZPdjXMWinsyqr6B+O7rDl
i8z0zy1BoxlgGoG/oC6p47v/1FWuYWB2KDSNpbtsjEZ1jWOqxxRlQYumN9ohAIWE
TR6Hu20tAgMBAAECggEAGicSJEByqnLXC3O+dG5Zp6T/GXFLH2ttM45+3euyO8re
hxLfuflH911tO6Yx1fxk3DZ1u3AaFIpzd52bEza46a8c5L259C7Xu+NwjQmupdRP
0y0P29La33X0LztW671eUUNgi6L7sCXKgn2PxbpT8pEewtEbDxdL2J5kUT8i9ni/
e5LDw0YmpLQfI05IQZvpWIlptotEYD+nirRsXcnciLFun/8ZIqPXPF3Ucyl7p0D5
BbZYM34rKYX1fWzDaf9B4fvSWAMtm9MrHuwo27zCq37M11peqXT7gZJxQTEeLrdk
+T65CX6j1LGO39GKQ2wwyqrUTuSu+qkZpk7tSa1BuQKBgQD97JT7MwBME9INUJxF
qoW2rIc3bS13BQ0+r+9U7wkUoqapS6oZEgBzCNoaf43+p326AoM0O5W1pgX7lHFf
VZE4sUWPmNuhxD7lKzThqvWntuF4mMCPVOW956ZQsbtrIonaUKQy4x2mNx9O91ob
N/mwqXCXWRigVhucg7OLMSLcpQKBgQDO01ng0wV4esHr9/twNiAfoSSGKA/sefl6
WpGH4mqUY2qAHoSPwict5zz2Vm3WJZXJtOnv9+v+z2P+IMsR8EgHS1Yh1vfhpNIp
YU2C46RkfsjB1Am8P5yS8+VI79FvGvrqn2KdPYzv6m1LSQZp/n1RQubyo8p/unPl
TiKfjaQ/6QKBgA66HvXmwlinOaKOD1I3DqRGo10ClwV1JIyDNbVOW893k4T0H3xu
v9nsJIIu7bRcUH1uUd/AqPEtHOG3fU/TLaYFGgy3B938/Mzb0ahY+wBsKe2NpnVp
rh1yhwHdHQqcqTQhQzS0WW7feZBh5jb36yJk4WPVxgjelaFhPhOPmP8FAoGAVxht
it2SOjAHpaTh/1jroiYryUrpmb2rrzigfEZ+d0p+OMGhNSCfexcbdujijAF72FsV
AHa4rK8M/qE0orM6wceZ19o8vIq57a8KAwp12dQCGo1+JAXtm3yVm2dSHKWR8Gd6
EZkv1oAz0jZIOy5t+2Be/OK4jZ0o3PFQZzwwZLECgYEArnuJEQlMQlxIyeMNaufb
Qsrd06UDWQPVaUMbs1W0WYklZFIJdzkAuucfArxOtc6HbeSv7jANzt6LjGnDdMTH
w0tTP1kImUOVPqMKaxcd/uC/VqgZtZ9la6jBloWstZ9LNWaxH1lrg1bW1ZSHvW8r
4qWsvM4Ddjtj5curHqBB9Jw=
-----END PRIVATE KEY-----`
	dataToSign    = `cGwuYnBpZXRyeWthLnBpdi5ub3RhdGlvbi5wbHVnaW4=`
	signatureText = `E97dWlLxdrkEpJgxlnB4mCTA2vDHLQ6LjafCkF/Rm+oeIn6eh+eVB6XllDPcry94aNwUBWfqRz3elVN7EQbXOyn26YMpahFMycsfx0RbUhhjzmUXYUhafOB2XR+H0GrryYqnlvSx4bgNkcXhwYt1C/VcnQLeCtI9PYXC04DLmJItd6tacLGcwmiTZaFCL8a4nKM/3yU4Qghkp9yLIf7RIUeHzrw9h6XKgK5zvwt68qtRbt3a04O4+eu0HuVFYuZuHjU7ivi6poNvYdPzZfCpRlbymgY1pGQ78xV35Oomx3sJLZWCFgC1LEeO9kw6d3QWHMpzuViYrG1S6txFHTOLhw==`
)

func parsePEMCertificates(data []byte) []*x509.Certificate {
	var certs []*x509.Certificate
	block, rest := pem.Decode(data)
	// data is in PEM format
	for block != nil {
		cert, _ := x509.ParseCertificate(block.Bytes)
		certs = append(certs, cert)
		block, rest = pem.Decode(rest)
	}
	return certs
}

func TestGetCertChainFromFileSelfSigned(t *testing.T) {
	certificates, err := GetCertChainFromFile(context.TODO(), "./../../test/example_certs/code_signing.crt")
	if err != nil {
		t.Errorf("Error found in GetCertChainFromFile: %v", err)
	}
	if len(certificates) != 1 {
		t.Error("There should be exactly one self-signed certificate")
	}
	block, _ := pem.Decode([]byte(testSelfSignedCertificateText))
	cert, _ := x509.ParseCertificate(block.Bytes)
	if !cert.Equal(certificates[0]) {
		t.Error("Certifcate read from file does not match")
	}
}

func TestGetCertChainFromFileChain(t *testing.T) {
	publicCertificates, err := GetCertChainFromFile(context.TODO(), "./../../test/example_certs/code_signing_chain.crt")
	if err != nil {
		t.Errorf("Error found in GetCertChainFromFile: %v", err)
	}
	testCertificateChain := parsePEMCertificates([]byte(testCertificateChainText))
	for i, cert := range testCertificateChain {
		if !cert.Equal(publicCertificates[i]) {
			t.Errorf("Certifcate no. %d in chain does not match", i)
		}
	}
}

func TestGetKeyAndCertChainFromFile(t *testing.T) {
	privateKeyInterface, publicCertificates, err := GetKeyAndCertChainFromFile(context.TODO(), "./../../test/example_certs/code_signing_chain.key", "./../../test/example_certs/code_signing_chain.crt")
	if err != nil {
		t.Errorf("Error found in GetKeyAndCertChainFromFile: %v", err)
	}
	testCertificateChain := parsePEMCertificates([]byte(testCertificateChainText))
	for i, cert := range testCertificateChain {
		if !cert.Equal(publicCertificates[i]) {
			t.Errorf("Certifcate no. %d in chain does not match", i)
		}
	}
	options := &rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: rsa.PSSSaltLengthEqualsHash}
	noRandom := strings.NewReader("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	dataToSighHash := sha256.Sum256([]byte(dataToSign))
	signatureByte, err := privateKeyInterface.(crypto.Signer).Sign(noRandom, dataToSighHash[:], options)
	if err != nil {
		t.Errorf("Error found in GetKeyAndCertChainFromFile: %v", err)
	}
	signature64 := base64.StdEncoding.EncodeToString(signatureByte)
	if signatureText != signature64 {
		t.Errorf("Gernetated signature does not match template: %v", signature64)
	}
}
