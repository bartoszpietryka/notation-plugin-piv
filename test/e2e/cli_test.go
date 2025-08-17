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

package e2e

import (
	"encoding/json"
	"flag"
	"io"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

var sigGenPluginPath = flag.String("sig_gen_plugin", "./bin/signaturegenerator/com.example.plugin", "dir of package containing embedded files")

func TestSuccess(t *testing.T) {
	tests := map[string]struct {
		pluginPath     *string
		stdin          string
		expectedStdout string
	}{
		"get-plugin-metadata": {
			pluginPath:     sigGenPluginPath,
			stdin:          "{}",
			expectedStdout: "{\"name\":\"com.example.plugin\",\"description\":\"This is an description of example plugin\",\"version\":\"1.0.0\",\"url\":\"https://example.com/notation/plugin\",\"supportedContractVersions\":[\"1.0\"],\"capabilities\":[\"SIGNATURE_GENERATOR.RAW\",\"SIGNATURE_VERIFIER.TRUSTED_IDENTITY\",\"SIGNATURE_VERIFIER.REVOCATION_CHECK\"]}"},
		"verify-signature": {
			pluginPath:     sigGenPluginPath,
			stdin:          "{\"contractVersion\":\"1.0\",\"signature\":{\"criticalAttributes\":{\"contentType\":\"someCT\",\"signingScheme\":\"someSigningScheme\"},\"unprocessedAttributes\":null,\"certificateChain\":[\"emFw\",\"em9w\"]},\"trustPolicy\":{\"trustedIdentities\":null,\"signatureVerification\":[\"SIGNATURE_GENERATOR.RAW\"]}}",
			expectedStdout: "{\"verificationResults\":{\"SIGNATURE_VERIFIER.REVOCATION_CHECK\":{\"success\":true,\"reason\":\"Not revoked\"},\"SIGNATURE_VERIFIER.TRUSTED_IDENTITY\":{\"success\":true,\"reason\":\"Valid trusted Identity\"}},\"processedAttributes\":[]}"},
		"version": {
			pluginPath:     sigGenPluginPath,
			stdin:          "",
			expectedStdout: "com.example.plugin - This is an description of example plugin\nVersion: 1.0.0\n",
		},
		"generate-signature": {
			pluginPath:     sigGenPluginPath,
			stdin:          "{\"contractVersion\":\"1.0\",\"keyId\":\"someKeyId\",\"keySpec\":\"EC-384\",\"hashAlgorithm\":\"SHA-384\",\"payload\":\"em9w\"}",
			expectedStdout: "{\"keyId\":\"someKeyId\",\"signature\":\"Z2VuZXJhdGVkTW9ja1NpZ25hdHVyZQ==\",\"signingAlgorithm\":\"RSASSA-PSS-SHA-384\",\"certificateChain\":[\"bW9ja0NlcnQx\",\"bW9ja0NlcnQy\"]}",
		},
		"describe-key": {
			pluginPath:     sigGenPluginPath,
			stdin:          "{\"contractVersion\":\"1.0\",\"keyId\":\"someKeyId\"}",
			expectedStdout: "{\"keyId\":\"someKeyId\",\"keySpec\":\"RSA-3072\"}",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			validateSuccess(*test.pluginPath, name, test.stdin, test.expectedStdout, t)
		})
	}
}

func TestFailure(t *testing.T) {
	cmds := []string{"verify-signature", "get-plugin-metadata"}
	stdInputs := []string{"", "\n", "invalidjson", "🍺 ¢ §"}
	expectedValidationErr := "{\"errorCode\":\"VALIDATION_ERROR\",\"errorMessage\":\"Input is not a valid JSON\"}"
	for _, cmd := range cmds {
		for _, input := range stdInputs {
			t.Run(cmd+"_"+input, func(t *testing.T) {
				validateFailure(*sigGenPluginPath, cmd, input, expectedValidationErr, t)
			})
		}
	}

	// get-plugin-metadata input has all of its keys as optional so ommiting it
	cmds = cmds[:len(cmds)-1]
	input := "{\"sad\":\"bad\"}"
	expectedValidationErr = "{\"errorCode\":\"VALIDATION_ERROR\",\"errorMessage\":\"Input is not a valid JSON: contractVersion cannot be empty\"}"
	for _, cmd := range cmds {
		t.Run(cmd+"_{}"+input, func(t *testing.T) {
			validateFailure(*sigGenPluginPath, cmd, input, expectedValidationErr, t)
		})
	}

	cmds = []string{"generate-signature", "describe-key"}
	stdInputs = []string{"", "\n", "invalidjson", "🍺 ¢ §"}
	expectedValidationErr = "{\"errorCode\":\"VALIDATION_ERROR\",\"errorMessage\":\"Input is not a valid JSON\"}"
	for _, cmd := range cmds {
		for _, input := range stdInputs {
			t.Run(cmd+"_"+input, func(t *testing.T) {
				validateFailure(*sigGenPluginPath, cmd, input, expectedValidationErr, t)
			})
		}
	}
}

func execute(exe, arg, stdInput string, t *testing.T) (string, string, error) {
	cmd := exec.Command(exe, arg)

	if stdInput != "" {
		stdin, err := cmd.StdinPipe()
		if err != nil {
			t.Errorf("something went wrong when trying to invoke example plugin by cli: %+v", err)
		}

		go func() {
			defer stdin.Close()
			io.WriteString(stdin, stdInput)
		}()
	}

	var stdOut strings.Builder
	var stdErr strings.Builder
	cmd.Stdout = &stdOut
	cmd.Stderr = &stdErr
	err := cmd.Run()

	return stdOut.String(), stdErr.String(), err
}

func validateSuccess(exe, arg, stdInput, expectedStdOut string, t *testing.T) {
	stdOut, stdErr, err := execute(exe, arg, stdInput, t)

	if err != nil {
		t.Logf("standard output: %s", stdOut)
		t.Logf("standard Err: %s", stdErr)
		t.Fatalf("'%s' command failed with error: %+v", arg, err)
	}

	if stdOut == "" {
		t.Errorf("For '%s' command's standard out must not be empty", arg)
	}

	if stdErr != "" {
		t.Errorf("For '%s' command's standard error must be empty", arg)
	}

	res, err := jsonEquals(stdOut, expectedStdOut)
	if err == nil {
		if !res {
			t.Errorf("For '%s' command, expected standard out to be '%s' but found '%s'", arg, expectedStdOut, stdOut)
		}
	} else {
		if expectedStdOut != stdOut {
			t.Errorf("For '%s' command, expected standard standard to be '%s' but found '%s'", arg, expectedStdOut, stdOut)
		}
	}

}

func validateFailure(exe, arg, stdInput, expectedStdError string, t *testing.T) {
	stdOut, stdErr, err := execute(exe, arg, stdInput, t)

	if err == nil {
		t.Fatalf("expected '%s' command fail with error but it didnt", arg)
		t.Logf("standard output: %s", stdOut)
		t.Logf("standard Err: %s", stdErr)
	}

	if stdErr == "" {
		t.Errorf("For '%s' command's standard error must not be empty", arg)
	}

	if stdOut != "" {
		t.Errorf("For '%s' command's standard out must be empty", arg)
	}

	if stdErr != expectedStdError {
		t.Errorf("For '%s' command, expected standard error to be '%s' but found '%s'", arg, expectedStdError, stdErr)
	}
}

// JSONEqual compares the JSON from two Readers.
func jsonEquals(x, y string) (bool, error) {
	var x1, y1 interface{}

	if err := json.Unmarshal([]byte(x), &x1); err != nil {
		return false, err
	}
	if err := json.Unmarshal([]byte(y), &y1); err != nil {
		return false, err
	}
	return reflect.DeepEqual(x1, y1), nil
}
