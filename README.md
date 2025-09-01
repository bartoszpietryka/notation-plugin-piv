# notation-plugin-piv
[Notation](https://github.com/notaryproject/notation) [plugin](https://github.com/notaryproject/specifications/blob/main/specs/plugin-extensibility.md) that allows to sign artifacts with [PIV](https://docs.yubico.com/yesdk/users-manual/application-piv/piv-overview.html) compatible HSM devices. Like YubiKey or SmartCard.  

This project uses [Notation plugin framework](https://github.com/notaryproject/notation-plugin-framework-go) as an foundation. And uses [piv-go](https://github.com/go-piv/piv-go) to interface with PIV devices

## Installation 

[Install notation](https://notaryproject.dev/docs/user-guides/installation/cli/)

 **Windows**:
On Windows necessary PIV driver should already by installed. It's is highly recommended to change default PIN before running this tool.

 Install plugin 
``` 
notation.exe plugin install --url https://github.com/bartoszpietryka/notation-plugin-piv/releases/download/Release_1_0_0/notation-plugin-piv_1.0.0_windows_amd64.zip --sha256sum 73bd7aabc488d98b3d257837d4558dc54e523e5cafae0146e8c7b37bf4f549e8
``` 
 **Linux**:
 To use on Linux, you'll need to install libraries for your PIV device first.

 On Debian based systems, Yubico PIV tool library can be installed with command:
```   
sudo apt install libykpiv2 
```
 Install plugin 
AMD64:
```
notation plugin install --url https://github.com/bartoszpietryka/notation-plugin-piv/releases/download/Release_1_0_0/notation-plugin-piv_1.0.0_linux_amd64.tar.gz --sha256sum b7c0866f89970dd70683f78555804c869333710894c5e88edf2592b458e76342
```
ARM64:
```
notation plugin install --url https://github.com/bartoszpietryka/notation-plugin-piv/releases/download/Release_1_0_0/notation-plugin-piv_1.0.0_linux_arm64.tar.gz --sha256sum a021eb5b20ce749b80fb517502e989502e8fcfe2505d86150b1872db5fa60a97

```

 To build on Linux you will additionally need to install libpcsclite-dev package
```
sudo apt install libpcsclite-dev
```

## Keys and Certificates
Currently notation-plugin-piv supports only RSA 2048 Keys

Notation has strict [requirments](https://github.com/notaryproject/specifications/blob/main/specs/signature-specification.md#certificate-requirements) for signing certificate and certificate chain. 
To generate proper certificates you can use openssl configuration examples from directory [test/example_certs](https://github.com/bartoszpietryka/notation-plugin-piv/tree/main/test/example_certs)

You will need to import code signing certificate and matching key into slot 9c on PIV device.

## Usage

Notation uses authentication token from ~/.docker/config.json . Login to repository with docker or [oras](https://oras.land/docs/installation) before signing

To sign container with self-signed certificate use
```   
notation.exe sign --plugin pl.bpietryka.piv.notation.plugin --id 1 --plugin-config PIN="234567" 123456.dkr.ecr.eu-west-1.amazonaws.com/signing@sha256:026b948169ecedce2dd53c005720dcc4fc8463d641d9aea32e9d3de5d2b8985a
```   

Self-signed code signing certificates are useful for testing environments. But for production environment, it is considered good practice to use Certificate Authority. 
In typical scenarios it's better to use Private than Public Certificate Authority. In other words use self-signed Root CA. 

PIV devices allow only one certificate in "Digital Signature" slot (9c). Unfortunately entire certificate chain cannot be imported into this slot. 
To circumnavigate this limitation, it's necessary to provide notation-plugin-piv with file that contains entire chain: Root CA, all Intermediate certificates and Leaf Certificate .

```   
notation.exe sign --plugin pl.bpietryka.piv.notation.plugin --id 1 --plugin-config PIN="234567" --plugin-config cert_path=test/example_certs/code_signing_chain.crt 123456.dkr.ecr.eu-west-1.amazonaws.com/signing@sha256:026b948169ecedce2dd53c005720dcc4fc8463d641d9aea32e9d3de5d2b8985a
```  

If you are using certificate chain, leaf code signing certificate must be imported into 9c slot. And Root CA (i.e. test/example_certs/RootCA.crt) certificate added to trust store, for verification 
```  
notation.exe cert add --type ca --store piv-example test/example_certs/RootCA.crt 
```  

## Ratify

When [deploying ratify](https://ratify.dev/docs/1.0/quickstarts/ratify-on-aws/#deploy-ratify), use  Root CA in --set-file parameter. i.e.
```  
notation cert list

helm install ratify ratify/ratify --atomic \
    --namespace gatekeeper-system \
    --set-file notationCert={./test/example_certs/RootCA.crt}
```  

If you are not using Root CA, you should use code_signing.crt, the same file that was imported into PIV device.

Please note that ratify expect certificate to be valid for at least 60 more days, otherwise it will throw error.

Please beware that in most instructions and tutorials for Ratify, they are using Gatekeeper constraint https://notaryproject.github.io/ratify/library/default/samples/constraint.yaml . This constraint verifies only signatures for pods created in "default" namespace. 

This is not sufficient for production environments . You can instead use constraint https://bartoszpietryka.github.io/notation-plugin-piv.github.io/ratify/library/samples/constraint.yaml . It requires verification of images signatures in all namespaces with exception of kube-system,gatekeeper-system .


## Code of Conduct

This project has adopted the [CNCF Code of Conduct](https://github.com/cncf/foundation/blob/master/code-of-conduct.md). See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for further details.

## License

This project is covered under the Apache 2.0 license. You can read the license [here](LICENSE).
