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
		AuthStyle:      oauth2.AuthStyle(oauth.AuthStyle),
	}
	cli := c.Client(context.Background())
	return func(_ context.Context) *http.Client {
		return cli
	}
}

// Config is the custom config struct containing the params for the golang.org/x/oauth2/clientcredentials package
type Config struct {
	IsDisabled     bool
	ClientID       string
	ClientSecret   string
	TokenURL       string
	Scopes         string
	EndpointParams map[string][]string
	AuthStyle      int
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
			values := []string{}
			for _, v := range vs.([]interface{}) {
				values = append(values, v.(string))
			}
			res[k] = values
		}
		cfg.EndpointParams = res
	}
	if v, ok := tmp["auth_style"]; ok {
		cfg.AuthStyle = int(v.(float64))
	}
	return cfg
}
