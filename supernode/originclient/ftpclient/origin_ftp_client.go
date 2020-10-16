/*
 * Copyright The Dragonfly Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package ftpclient

import (
	"github.com/dragonflyoss/Dragonfly/supernode/originclient"
	"github.com/go-openapi/strfmt"
)

// OriginFTPClient is an implementation of the interface of OriginClient.
type OriginFTPClient struct {

}

// NewOriginClient returns a new OriginClient.
func NewOriginFTPClient() originclient.OriginClient {
	return &OriginFTPClient{}
}

func (client *OriginFTPClient) RegisterTLSConfig(rawURL string, insecure bool, caBlock []strfmt.Base64) {

}

func (client *OriginFTPClient) GetContentLength(url string, headers map[string]string) (int64, int, error) {

}

func (client *OriginFTPClient) IsSupportRange(url string, headers map[string]string) (bool, error) {

}

func (client *OriginFTPClient) IsExpired(url string, headers map[string]string, lastModified int64, eTag string) (bool, error) {

}

func (client *OriginFTPClient) Download(url string, headers map[string]string, checkCode originclient.StatusCodeChecker) (*originclient.FileResult, error) {

}


