package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDcRegionFromCredential(t *testing.T) {
	tests := []struct {
		credential string
		want       dcRegion
	}{
		{"us_eyJabc", dcRegionUs},
		{"ap_eyJabc", dcRegionAp},
		{"hk_eyJabc", dcRegionAp},
		{"eyJabc", dcRegionAp},
		{"", dcRegionAp},
		{"Bearer us_eyJabc", dcRegionUs},
		{"Bearer ap_eyJabc", dcRegionAp},
		{"Bearer eyJabc", dcRegionAp},
	}
	for _, tc := range tests {
		got := dcRegionFromCredential(tc.credential)
		if got != tc.want {
			t.Errorf("dcRegionFromCredential(%q) = %v, want %v", tc.credential, got, tc.want)
		}
	}
}

func TestDcRegionFromCredentials(t *testing.T) {
	if dcRegionFromCredentials("ap_key", "us_secret", "ap_token") != dcRegionUs {
		t.Error("expected Us when any credential is us_")
	}
	if dcRegionFromCredentials("ap_key", "ap_secret", "ap_token") != dcRegionAp {
		t.Error("expected Ap when all credentials are ap_")
	}
	if dcRegionFromCredentials() != dcRegionAp {
		t.Error("expected Ap for empty credentials")
	}
}

func TestDcRegionAsStr(t *testing.T) {
	if dcRegionUs.asStr() != "us" {
		t.Error("Us.asStr() should be 'us'")
	}
	if dcRegionAp.asStr() != "ap" {
		t.Error("Ap.asStr() should be 'ap'")
	}
}

func TestStripRegionPrefix(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"ap_token", "token"},
		{"us_token", "token"},
		{"token", "token"},
		{"Bearer ap_token", "token"},
	}
	for _, tc := range tests {
		got := stripRegionPrefix(tc.input)
		if got != tc.want {
			t.Errorf("stripRegionPrefix(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestClientCallStripsRegionPrefixFromAuthorization(t *testing.T) {
	tests := []struct {
		name        string
		accessToken string
		appKey      string
		wantToken   string
		wantRegion  string
	}{
		{"ap token", "ap_token", "ap_key", "token", "ap"},
		{"us token", "us_token", "us_key", "token", "us"},
		{"unprefixed token", "token", "key", "token", "ap"},
		{"bearer ap token", "Bearer ap_token", "ap_key", "token", "ap"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := r.Header.Get("Authorization"); got != tc.wantToken {
					t.Errorf("Authorization = %q, want %q", got, tc.wantToken)
				}
				if got := r.Header.Get(dcRegionHeader); got != tc.wantRegion {
					t.Errorf("%s = %q, want %q", dcRegionHeader, got, tc.wantRegion)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"code":0}`))
			}))
			defer server.Close()

			client, err := New(
				WithURL(server.URL),
				WithAccessToken(tc.accessToken),
				WithAppKey(tc.appKey),
				WithAppSecret("secret"),
			)
			if err != nil {
				t.Fatal(err)
			}
			if err := client.Get(context.Background(), "/v1/test", nil, nil); err != nil {
				t.Fatal(err)
			}
		})
	}
}
