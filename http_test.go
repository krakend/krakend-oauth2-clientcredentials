package oauth2client

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luraproject/lura/v2/config"
)

type TestConfig struct {
	ClientId                string
	ClientSecret            string
	Scopes                  string
	Audience                string
	Token                   string
	ExpectedAuthTokenHeader string
	ExpectedResponseBody    string
}

func (t *TestConfig) prepareTokenServer(testing *testing.T) *httptest.Server {
	var tokenIssued atomic.Value

	tokenIssued.Store(false)
	expectedValues := url.Values{
		"audience":   {t.Audience},
		"grant_type": {"client_credentials"},
	}
	expectedBody := fmt.Sprintf("%s&scope=%s", expectedValues.Encode(), strings.ReplaceAll(t.Scopes, ",", "+"))

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if tokenIssued.Load().(bool) {
			testing.Error("token issuer was asked for more than a single token")
			return
		}
		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			testing.Error("unexpected content type:", r.Header.Get("Content-Type"))
			return
		}
		body, err := io.ReadAll(r.Body)
		r.Body.Close()
		if err != nil {
			log.Println(err)
			return
		}
		s := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
		if len(s) != 2 {
			testing.Error("Not authorized", s)
			return
		}
		b, err := base64.StdEncoding.DecodeString(s[1])
		if err != nil {
			testing.Error(err.Error())
			return
		}

		pair := strings.SplitN(string(b), ":", 2)
		if len(pair) != 2 {
			testing.Error("Not authorized", pair)
			return
		}
		if pair[0] != t.ClientId || pair[1] != t.ClientSecret {
			testing.Error("Not authorized", pair)
			return
		}
		if string(body) != expectedBody {
			testing.Error("unexpected body! have:", string(body), "want:", expectedBody)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":"%s","expires_in":3600,"token_type":"bearer"}`, t.Token)
		tokenIssued.Store(true)
	}))
}

func (t *TestConfig) prepareTestServer(testing *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(t.ExpectedAuthTokenHeader) != fmt.Sprintf("Bearer %s", t.Token) {
			testing.Error("unexpected token:", r.Header.Get(t.ExpectedAuthTokenHeader))
			return
		}
		fmt.Fprint(w, t.ExpectedResponseBody)
	}))
}

func TestClient(t *testing.T) {
	testConfig := &TestConfig{
		ClientId:                "some_client_id",
		ClientSecret:            "some_client_secret",
		Scopes:                  "scope1,scope2",
		Audience:                "http://api.example.com",
		Token:                   "03807cb390319329bdf6c777d4dfae9c0d3b3c35",
		ExpectedAuthTokenHeader: "Authorization",
		ExpectedResponseBody:    "Hello, client",
	}
	tokenServer := testConfig.prepareTokenServer(t)
	defer tokenServer.Close()

	ts := testConfig.prepareTestServer(t)
	defer ts.Close()

	c := NewHTTPClient(&config.Backend{
		ExtraConfig: map[string]interface{}{
			Namespace: map[string]interface{}{
				"client_id":     testConfig.ClientId,
				"client_secret": testConfig.ClientSecret,
				"token_url":     tokenServer.URL,
				"scopes":        testConfig.Scopes,
				"endpoint_params": map[string]interface{}{
					"audience": []interface{}{testConfig.Audience},
				},
			},
		},
	})
	client := c(context.Background())

	for i := 0; i < 5; i++ {
		resp, err := client.Get(ts.URL)
		if err != nil {
			log.Println(err)
			t.Error(err)
			return
		}
		response, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			log.Println(err)
			t.Error(err)
			return
		}
		if string(response) != testConfig.ExpectedResponseBody {
			t.Error("unexpected body:", string(response))
		}
	}
}

func TestCustomAuthHeaderClient(t *testing.T) {
	testConfig := &TestConfig{
		ClientId:                "some_client_id",
		ClientSecret:            "some_client_secret",
		Scopes:                  "scope1,scope2",
		Audience:                "http://api.example.com",
		Token:                   "03807cb390319329bdf6c777d4dfae9c0d3b3c35",
		ExpectedAuthTokenHeader: "X-Custom-Header",
		ExpectedResponseBody:    "Hello, client",
	}

	tokenServer := testConfig.prepareTokenServer(t)
	defer tokenServer.Close()

	ts := testConfig.prepareTestServer(t)
	defer ts.Close()

	c := NewHTTPClient(&config.Backend{
		ExtraConfig: map[string]interface{}{
			Namespace: map[string]interface{}{
				"client_id":        testConfig.ClientId,
				"client_secret":    testConfig.ClientSecret,
				"auth_header_name": testConfig.ExpectedAuthTokenHeader,
				"token_url":        tokenServer.URL,
				"scopes":           testConfig.Scopes,
				"endpoint_params": map[string]interface{}{
					"audience": []interface{}{testConfig.Audience},
				},
			},
		},
	})
	client := c(context.Background())

	for i := 0; i < 5; i++ {
		resp, err := client.Get(ts.URL)
		if err != nil {
			log.Println(err)
			t.Error(err)
			return
		}
		response, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			log.Println(err)
			t.Error(err)
			return
		}
		if string(response) != testConfig.ExpectedResponseBody {
			t.Error("unexpected body:", string(response))
		}
	}
}
