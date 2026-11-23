package oidc

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUserInfoEmailVerifiedClaim(t *testing.T) {
	cases := []struct {
		name     string
		claims   string
		expected bool
	}{
		{"boolean true", `{"email":"a@example.com","email_verified":true}`, true},
		{"boolean false", `{"email":"a@example.com","email_verified":false}`, false},
		{"string true", `{"email":"a@example.com","email_verified":"true"}`, true},
		{"string false", `{"email":"a@example.com","email_verified":"false"}`, false},
		{"string TRUE is not accepted", `{"email":"a@example.com","email_verified":"TRUE"}`, false},
		{"absent", `{"email":"a@example.com"}`, false},
		{"null", `{"email":"a@example.com","email_verified":null}`, false},
		{"number", `{"email":"a@example.com","email_verified":1}`, false},
		{"object", `{"email":"a@example.com","email_verified":{"x":1}}`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var info UserInfo
			require.NoError(t, json.Unmarshal([]byte(c.claims), &info))
			assert.Equal(t, c.expected, bool(info.EmailVerified))
			assert.Equal(t, "a@example.com", info.Email)
		})
	}
}

// A malformed email_verified claim must not stop the other claims from being read.
func TestUserInfoMalformedEmailVerifiedKeepsOtherClaims(t *testing.T) {
	var info UserInfo
	require.NoError(t, json.Unmarshal([]byte(`{"sub":"s1","name":"bob","email":"b@example.com","email_verified":"yes"}`), &info))
	assert.False(t, bool(info.EmailVerified))
	assert.Equal(t, "s1", info.Subject)
	assert.Equal(t, "bob", info.Username)
}

func TestMergeUserInfoCarriesEmailVerifiedFromRemote(t *testing.T) {
	remote := &UserInfo{Subject: "s1", Email: "r@example.com", EmailVerified: true}
	local := &UserInfo{Subject: "s1", Issuer: "https://idp", Email: "l@example.com", EmailVerified: false}
	merged := mergeUserInfo(remote, local)
	assert.Equal(t, "r@example.com", merged.Email)
	assert.True(t, bool(merged.EmailVerified))
}
