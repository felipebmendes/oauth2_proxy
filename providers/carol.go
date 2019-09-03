package providers

import (
	"fmt"
	"io/ioutil"
	"net/url"
	"strings"

	"github.com/pusher/oauth2_proxy/pkg/apis/sessions"
	"github.com/pusher/oauth2_proxy/pkg/logger"
	"github.com/pusher/oauth2_proxy/pkg/requests"
)

// CarolProvider represents an Carol based Identity Provider
type CarolProvider struct {
	*ProviderData
}

// NewCarolProvider initiates a new CarolProvider
func NewCarolProvider(p *ProviderData) *CarolProvider {
	p.ProviderName = "Carol"
	if p.ValidateURL == nil || p.ValidateURL.String() == "" {
		p.ValidateURL = &url.URL{
			Scheme: "https",
			//Host:   "%s.%s.%s.ai",
			Host: "%s.%s.ai",
			Path: "/api/v2/oauth2/token/",
		}
	}
	return &CarolProvider{ProviderData: p}
}

// ValidateSessionState returns the Client Id
func (p *CarolProvider) ValidateSessionState(s *sessions.SessionState) bool {
	accessToken := s.AccessToken
	if accessToken == "" || p.Data().ValidateURL == nil || p.Data().ValidateURL.String() == "" || s.Email == "" {
		return false
	}
	logger.Printf("Req info: email:%s", s.Email)
	parts := strings.Split(s.Email, ".")
	if len(parts) != 2 {
		return false
	}
	logger.Printf("Req info: tenant:%s", parts[0])
	logger.Printf("Req info: env:%s", parts[1])
	url := &url.URL{
		Scheme: p.Data().ValidateURL.Scheme,
		Host:   fmt.Sprintf(p.Data().ValidateURL.Host, parts[0], parts[1]),
		Path:   p.Data().ValidateURL.Path,
	}
	logger.Printf("Req info: url:%s", url.String())
	endpoint := url.String() + accessToken
	logger.Printf("Req info: endpoint:%s", endpoint)
	resp, err := requests.RequestUnparsedResponse(endpoint, nil)
	if err != nil {
		logger.Printf("GET %s", stripToken(endpoint))
		logger.Printf("token validation request failed: %s", err)
		return false
	}

	body, _ := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	logger.Printf("%d GET %s %s", resp.StatusCode, stripToken(endpoint), body)

	if resp.StatusCode == 200 {
		return true
	}
	logger.Printf("token validation request failed: status %d - %s", resp.StatusCode, body)
	return false
}
