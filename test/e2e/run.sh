#!/bin/bash -e

# Copyright The Notary Project Authors.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# build PIV plugin for e2e tests
echo "building plugin..."
echo "=============================="
CWD=$(pwd)
PLUGIN_NAME=com.bp.piv.notation.plugin
plugin_directories=(  signaturegenerator )
for plugin_directory in "${plugin_directories[@]}"
do
  (cd "../../PIV/${plugin_directory}" && go build -o "$CWD/bin/${plugin_directory}/$PLUGIN_NAME" . && echo "e2e ${plugin_directory} plugin built")
done

# run e2e tests
echo "running e2e tests..."
echo "=============================="
go test  -v ./... -args -sig_gen_plugin="./bin/${plugin_directories[0]}/$PLUGIN_NAME"
