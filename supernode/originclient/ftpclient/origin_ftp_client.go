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
	"fmt"
	ftp "github.com/dragonflyoss/Dragonfly/pkg/ftputils"
	"github.com/dragonflyoss/Dragonfly/supernode/originclient"
	"github.com/go-openapi/strfmt"
	"strings"
	"time"

	neturl "net/url"
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
	var (
		meta *originclient.FileResult
		err  error
	)

	if meta, err = client.getFileMeta(url); err != nil {
		return 0, 0, err
	}
	return meta.Size, 200, nil
}

func (client *OriginFTPClient) IsSupportRange(url string, headers map[string]string) (bool, error) {
	return false, nil
}

func (client *OriginFTPClient) IsExpired(url string, headers map[string]string, lastModified int64, eTag string) (bool, error) {
	var (
		meta *originclient.FileResult
		err  error
	)

	if meta, err = client.getFileMeta(url); err != nil {
		return false, err
	}
	return meta.LastModified != lastModified, nil
}

func (client *OriginFTPClient) Download(url string, headers map[string]string, checkCode originclient.StatusCodeChecker) (*originclient.FileResult, error) {
	var (
		urlInfo *neturl.URL
		err     error
	)

	if urlInfo, err = neturl.Parse(url); err != nil {
		return nil, err
	}

	colonPos := strings.LastIndex(urlInfo.Host, ":")
	if colonPos == -1 {
		urlInfo.Host = fmt.Sprintf("%s:21", urlInfo.Host)
	}

	cli, err := ftp.Dial(urlInfo.Host, ftp.DialWithTimeout(4*time.Second))
	if err != nil {
		return nil, err
	}

	if urlInfo.User != nil {
		if pwd, ok := urlInfo.User.Password(); ok {
			err = cli.Login(urlInfo.User.Username(), pwd)
			if err != nil {
				return nil, err
			}
		}
	}

	resp, err := cli.Retr(urlInfo.Path)
	if err != nil {
		return nil, err
	}
	return &originclient.FileResult{
		Body: resp,
	}, nil
}

func (client *OriginFTPClient) getFileMeta(url string) (*originclient.FileResult, error) {
	var (
		urlInfo *neturl.URL
		err     error
	)

	if urlInfo, err = neturl.Parse(url); err != nil {
		return nil, err
	}

	colonPos := strings.LastIndex(urlInfo.Host, ":")
	if colonPos == -1 {
		urlInfo.Host = fmt.Sprintf("%s:21", urlInfo.Host)
	}

	cli, err := ftp.Dial(urlInfo.Host, ftp.DialWithTimeout(4*time.Second))
	if err != nil {
		return nil, err
	}

	if urlInfo.User != nil {
		if pwd, ok := urlInfo.User.Password(); ok {
			err = cli.Login(urlInfo.User.Username(), pwd)
			if err != nil {
				return nil, err
			}
		}
	}

	entries, err := cli.List(urlInfo.Path)
	if len(entries) != 1 {
		return nil, fmt.Errorf("file(path: %s) not found", urlInfo.Path)
	}
	return &originclient.FileResult{
		LastModified: entries[0].Time.Unix(),
		Size:         int64(entries[0].Size),
	}, nil
}
