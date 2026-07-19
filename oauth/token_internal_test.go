package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/longbridgeapp/assert"
)

func useTemporaryHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	return home
}

func TestOAuth_Refresh(t *testing.T) {
	useTemporaryHome(t)
	refreshCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		refreshCalls++
		assert.Equal(t, "/oauth2/token", r.URL.Path)
		assert.NoError(t, r.ParseForm())
		assert.Equal(t, "refresh_token", r.Form.Get("grant_type"))
		assert.Equal(t, "old-refresh", r.Form.Get("refresh_token"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"new-access","refresh_token":"new-refresh","expires_in":7200,"token_type":"Bearer"}`))
	}))
	defer server.Close()

	o := NewWithBaseURL("client-id", server.URL)
	o.token = &oauthToken{
		AccessToken:  "old-access",
		RefreshToken: "old-refresh",
		ExpiresAt:    time.Now().Add(2 * time.Hour).Unix(),
	}

	assert.NoError(t, o.Refresh(context.Background()))
	assert.Equal(t, 1, refreshCalls)
	assert.Equal(t, "new-access", o.token.AccessToken)
	assert.Equal(t, "new-refresh", o.token.RefreshToken)

	path, err := o.tokenPath()
	assert.NoError(t, err)
	persisted, err := loadTokenFromPath(path)
	assert.NoError(t, err)
	assert.Equal(t, "new-access", persisted.AccessToken)
	assert.Equal(t, "new-refresh", persisted.RefreshToken)
}

func TestOAuth_RefreshIfCurrent_DoesNotRefreshStaleRejection(t *testing.T) {
	useTemporaryHome(t)
	refreshCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		refreshCalls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"new-access","expires_in":7200,"token_type":"Bearer"}`))
	}))
	defer server.Close()

	o := NewWithBaseURL("client-id", server.URL)
	o.token = &oauthToken{AccessToken: "old-access", RefreshToken: "refresh", ExpiresAt: time.Now().Add(2 * time.Hour).Unix()}

	assert.NoError(t, o.RefreshIfCurrent(context.Background(), "old-access"))
	assert.NoError(t, o.RefreshIfCurrent(context.Background(), "old-access"))
	assert.Equal(t, 1, refreshCalls)
}

func TestOAuth_RefreshRequiresReauthorization(t *testing.T) {
	t.Run("missing refresh token", func(t *testing.T) {
		o := New("client-id")
		o.token = &oauthToken{AccessToken: "access"}
		err := o.Refresh(context.Background())
		assert.True(t, errors.Is(err, ErrReauthorizationRequired))
	})

	t.Run("rejected refresh token", func(t *testing.T) {
		useTemporaryHome(t)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"refresh token revoked"}`))
		}))
		defer server.Close()

		o := NewWithBaseURL("client-id", server.URL)
		o.token = &oauthToken{AccessToken: "access", RefreshToken: "revoked", ExpiresAt: time.Now().Add(2 * time.Hour).Unix()}
		err := o.Refresh(context.Background())
		assert.True(t, errors.Is(err, ErrReauthorizationRequired))
	})
}

func Test_oauthToken_IsExpired(t *testing.T) {
	t.Run("not expired", func(t *testing.T) {
		tok := &oauthToken{
			AccessToken: "test",
			ExpiresAt:   time.Now().Unix() + 7200,
		}
		assert.False(t, tok.isExpired())
	})
	t.Run("expired", func(t *testing.T) {
		tok := &oauthToken{
			AccessToken: "test",
			ExpiresAt:   time.Now().Unix() - 1,
		}
		assert.True(t, tok.isExpired())
	})
}

func Test_oauthToken_ExpiresSoon(t *testing.T) {
	t.Run("expires soon (30 min)", func(t *testing.T) {
		tok := &oauthToken{
			AccessToken: "test",
			ExpiresAt:   time.Now().Unix() + 1800,
		}
		assert.True(t, tok.expiresSoon())
	})
	t.Run("not expires soon (2 hours)", func(t *testing.T) {
		tok := &oauthToken{
			AccessToken: "test",
			ExpiresAt:   time.Now().Unix() + 7200,
		}
		assert.False(t, tok.expiresSoon())
	})
}

func Test_oauthToken_JSONRoundtrip(t *testing.T) {
	tok := &oauthToken{
		AccessToken:  "test_access_token",
		RefreshToken: "test_refresh_token",
		ExpiresAt:    1234567890,
	}
	data, err := json.Marshal(tok)
	assert.NoError(t, err)
	var decoded oauthToken
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)
	assert.Equal(t, tok.AccessToken, decoded.AccessToken)
	assert.Equal(t, tok.RefreshToken, decoded.RefreshToken)
	assert.Equal(t, tok.ExpiresAt, decoded.ExpiresAt)
}
