package mgr

import (
	"github.com/dragonflyoss/Dragonfly/supernode/originclient"
	"github.com/dragonflyoss/Dragonfly/supernode/originclient/ftpclient"
	"github.com/dragonflyoss/Dragonfly/supernode/originclient/httpclient"
	neturl "net/url"
)

const (
	OriginHTTPSchema = "http"
	OriginFTPSchema  = "ftp"
)

type OriginClientManager struct {
	originClientMaps map[string]originclient.OriginClient
}

func NewOriginClientManager() *OriginClientManager {
	return &OriginClientManager{
		originClientMaps: map[string]originclient.OriginClient{
			OriginHTTPSchema: httpclient.NewOriginHTTPClient(),
			OriginFTPSchema:  ftpclient.NewOriginFTPClient(),
		},
	}
}

func (mgr *OriginClientManager) GetOriginClient(url string) originclient.OriginClient {
	var (
		urlInfo *neturl.URL
		err     error
	)

	if urlInfo, err = neturl.Parse(url); err != nil {
		return nil
	}

	return mgr.originClientMaps[urlInfo.Scheme]
}
