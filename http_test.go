package oauth2client

import (
	"context"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/devopsfaith/krakend/config"
)

func TestClient(t *testing.T) {
	clientID := "some_client_id"
	clientSecret := "some_client_secret"
	scopes := "scope1,scope2"
	audience := "http://api.example.com"

	token := "03807cb390319329bdf6c777d4dfae9c0d3b3c35"
	okidoki := "Hello, client"

	expectedValues := url.Values{
		"audience":   {audience},
		"grant_type": {"client_credentials"},
	}
	expectedBody := fmt.Sprintf("%s&scope=%s", expectedValues.Encode(), strings.Replace(scopes, ",", "+", -1))
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Error("unexpected content type:", r.Header.Get("Content-Type"))
			return
		}
		body, err := ioutil.ReadAll(r.Body)
		r.Body.Close()
		if err != nil {
			log.Println(err)
			return
		}
		s := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
		if len(s) != 2 {
			t.Error("Not authorized", s)
			return
		}
		b, err := base64.StdEncoding.DecodeString(s[1])
		if err != nil {
			t.Error(err.Error())
			return
		}

		pair := strings.SplitN(string(b), ":", 2)
		if len(pair) != 2 {
			t.Error("Not authorized", pair)
			return
		}
		if pair[0] != clientID || pair[1] != clientSecret {
			t.Error("Not authorized", pair)
			return
		}
		if string(body) != expectedBody {
			t.Error("unexpected body! have:", string(body), "want:", expectedBody)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":"%s","expires_in":3600,"token_type":"bearer"}`, token)
	}))
	defer tokenServer.Close()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != fmt.Sprintf("Bearer %s", token) {
			t.Error("unexpected token:", r.Header.Get("Authorization"))
			return
		}
		fmt.Fprint(w, okidoki)
	}))
	defer ts.Close()

	c := NewHTTPClient(&config.Backend{
		ExtraConfig: map[string]interface{}{
			Namespace: map[string]interface{}{
				"client_id":     clientID,
				"client_secret": clientSecret,
				"token_url":     tokenServer.URL,
				"scopes":        scopes,
				"endpoint_params": map[string]interface{}{
					"audience": []interface{}{audience},
				},
			},
		},
	})
	client := c(context.Background())

	resp, err := client.Get(ts.URL)
	if err != nil {
		log.Println(err)
		t.Error(err)
		return
	}
	response, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		log.Println(err)
		t.Error(err)
		return
	}
	if string(response) != okidoki {
		t.Error("unexpected body:", string(response))
	}
}
