package http

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/longbridge/openapi-go/oauth"
	"github.com/longbridgeapp/assert"
)

func TestClientCall_RetriesOnceAfterOAuthTokenRejection(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	apiCalls := 0
	refreshCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/oauth2/token":
			refreshCalls++
			_, _ = w.Write([]byte(`{"access_token":"new-access","refresh_token":"new-refresh","expires_in":7200,"token_type":"Bearer"}`))
		case "/v1/test":
			apiCalls++
			if r.Header.Get("authorization") == "Bearer old-access" && r.Header.Get(dcRegionHeader) == "ap" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"code":401102,"message":"token verification failed"}`))
				return
			}
			_, _ = w.Write([]byte(`{"code":0,"data":{"value":"ok"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	clientID := "client-id"
	tokenPath := filepath.Join(home, ".longbridge", "openapi", "tokens", clientID)
	assert.NoError(t, os.MkdirAll(filepath.Dir(tokenPath), 0700))
	tokenData, err := json.Marshal(map[string]interface{}{
		"access_token":  "ap_old-access",
		"refresh_token": "old-refresh",
		"expires_at":    time.Now().Add(2 * time.Hour).Unix(),
	})
	assert.NoError(t, err)
	assert.NoError(t, os.WriteFile(tokenPath, tokenData, 0600))

	oauthClient := oauth.NewWithBaseURL(clientID, server.URL)
	assert.NoError(t, oauthClient.Build(context.Background()))
	client, err := New(WithURL(server.URL), WithOAuthClient(oauthClient))
	assert.NoError(t, err)

	var result struct {
		Value string `json:"value"`
	}
	assert.NoError(t, client.Get(context.Background(), "/v1/test", nil, &result))
	assert.Equal(t, "ok", result.Value)
	assert.Equal(t, 2, apiCalls)
	assert.Equal(t, 1, refreshCalls)
}

func TestClientCall_DoesNotRetryTokenRejectionMoreThanOnce(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	apiCalls := 0
	refreshCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/oauth2/token" {
			refreshCalls++
			_, _ = w.Write([]byte(`{"access_token":"new-access","refresh_token":"new-refresh","expires_in":7200,"token_type":"Bearer"}`))
			return
		}
		apiCalls++
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"code":401102,"message":"token verification failed"}`))
	}))
	defer server.Close()

	clientID := "client-id"
	tokenPath := filepath.Join(home, ".longbridge", "openapi", "tokens", clientID)
	assert.NoError(t, os.MkdirAll(filepath.Dir(tokenPath), 0700))
	tokenData, err := json.Marshal(map[string]interface{}{
		"access_token":  "ap_old-access",
		"refresh_token": "old-refresh",
		"expires_at":    time.Now().Add(2 * time.Hour).Unix(),
	})
	assert.NoError(t, err)
	assert.NoError(t, os.WriteFile(tokenPath, tokenData, 0600))

	oauthClient := oauth.NewWithBaseURL(clientID, server.URL)
	assert.NoError(t, oauthClient.Build(context.Background()))
	client, err := New(WithURL(server.URL), WithOAuthClient(oauthClient))
	assert.NoError(t, err)

	err = client.Get(context.Background(), "/v1/test", nil, nil)
	var apiErr *ApiError
	assert.True(t, errors.As(err, &apiErr))
	assert.Equal(t, tokenVerificationFailedCode, apiErr.Code)
	assert.Equal(t, 2, apiCalls)
	assert.Equal(t, 1, refreshCalls)
}
