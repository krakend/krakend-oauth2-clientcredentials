package oauth2client

import (
	"context"
	"net/http"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/luraproject/lura/v2/config"
	"github.com/luraproject/lura/v2/transport/http/client"
)

// Namespace is the key to use to store and access the custom config data
const Namespace = "github.com/devopsfaith/krakend-oauth2-clientcredentials"

// NewHTTPClient creates a HTTPClientFactory with an http client configured for dealing
// with all the logic related to the oauth2 client credentials grant
func NewHTTPClient(cfg *config.Backend) client.HTTPClientFactory {
	oauth, ok := configGetter(cfg.ExtraConfig).(Config)
	if !ok || oauth.IsDisabled {
		return client.NewHTTPClient
	}
	c := clientcredentials.Config{
		ClientID:       oauth.ClientID,
		ClientSecret:   oauth.ClientSecret,
		TokenURL:       oauth.TokenURL,
		Scopes:         strings.Split(oauth.Scopes, ","),
		EndpointParams: oauth.EndpointParams,
	}
	var authHeaderName string

	if oauth.AuthHeaderName != "" {
		authHeaderName = oauth.AuthHeaderName
	} else {
		authHeaderName = "Authorization"
	}

	cli := &http.Client{
		Transport: &ConfigurableAuthHeaderTransport{
			AuthHeaderName: authHeaderName,
			Source:         oauth2.ReuseTokenSource(nil, c.TokenSource(context.Background())),
		},
	}
	return func(_ context.Context) *http.Client {
		return cli
	}
}

type ConfigurableAuthHeaderTransport struct {
	AuthHeaderName string
	Source         oauth2.TokenSource
}

func (t *ConfigurableAuthHeaderTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	reqBodyClosed := false
	if req.Body != nil {
		defer func() {
			if !reqBodyClosed {
				req.Body.Close()
			}
		}()
	}

	token, err := t.Source.Token()
	if err != nil {
		return nil, err
	}

	req2 := cloneRequest(req)
	req2.Header.Set(t.AuthHeaderName, token.Type()+" "+token.AccessToken)

	reqBodyClosed = true
	return http.DefaultTransport.RoundTrip(req2)
}

// Config is the custom config struct containing the params for the golang.org/x/oauth2/clientcredentials package
type Config struct {
	IsDisabled     bool
	AuthHeaderName string
	ClientID       string
	ClientSecret   string
	TokenURL       string
	Scopes         string
	EndpointParams map[string][]string
}

// ZeroCfg is the zero value for the Config struct
var ZeroCfg = Config{}

func configGetter(e config.ExtraConfig) interface{} {
	v, ok := e[Namespace]
	if !ok {
		return nil
	}
	tmp, ok := v.(map[string]interface{})
	if !ok {
		return nil
	}
	cfg := Config{}
	if v, ok := tmp["is_disabled"]; ok {
		cfg.IsDisabled = v.(bool)
	}
	if v, ok := tmp["auth_header_name"]; ok {
		cfg.AuthHeaderName = v.(string)
	}
	if v, ok := tmp["client_id"]; ok {
		cfg.ClientID = v.(string)
	}
	if v, ok := tmp["client_secret"]; ok {
		cfg.ClientSecret = v.(string)
	}
	if v, ok := tmp["token_url"]; ok {
		cfg.TokenURL = v.(string)
	}
	if v, ok := tmp["scopes"]; ok {
		cfg.Scopes = v.(string)
	}
	if v, ok := tmp["endpoint_params"]; ok {
		tmp = v.(map[string]interface{})
		res := map[string][]string{}
		for k, vs := range tmp {
			var values []string
			for _, v := range vs.([]interface{}) {
				values = append(values, v.(string))
			}
			res[k] = values
		}
		cfg.EndpointParams = res
	}
	return cfg
}

func cloneRequest(r *http.Request) *http.Request {
	// shallow copy of the struct
	r2 := new(http.Request)
	*r2 = *r
	// deep copy of the Header
	r2.Header = make(http.Header, len(r.Header))
	for k, s := range r.Header {
		r2.Header[k] = append([]string(nil), s...)
	}
	return r2
}
