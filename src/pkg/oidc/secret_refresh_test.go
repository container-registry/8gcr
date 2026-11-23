// Copyright Project Harbor Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/goharbor/harbor/src/common/models"
	"github.com/goharbor/harbor/src/common/utils"
	"github.com/goharbor/harbor/src/testing/mock"
	daoMock "github.com/goharbor/harbor/src/testing/pkg/oidc/dao"
)

const testEncryptKey = "naa4JtarA1Zsc3uY"

func encryptToken(t *testing.T, token *Token) string {
	t.Helper()
	tb, err := json.Marshal(token)
	require.NoError(t, err)
	enc, err := utils.ReversibleEncrypt(string(tb), testEncryptKey)
	require.NoError(t, err)
	return enc
}

// setupVerifySecret stubs the package level dependencies of VerifySecret and returns a manager whose DAO
// returns an OIDC user holding the secret "Secret123" and each of the given tokens on successive reads.
func setupVerifySecret(t *testing.T, username string, tokens ...*Token) (*defaultManager, *daoMock.MetaDAO) {
	t.Helper()
	oldKeyLoader, oldRefresh, oldUserInfo := keyLoader, refreshTokenFn, userInfoFromTokenFn
	keyLoader = &keyGetter{key: testEncryptKey}
	userInfoFromTokenFn = func(_ context.Context, tk *Token) (*UserInfo, error) {
		return &UserInfo{Username: username, Subject: tk.AccessToken}, nil
	}
	t.Cleanup(func() {
		keyLoader, refreshTokenFn, userInfoFromTokenFn = oldKeyLoader, oldRefresh, oldUserInfo
		refreshFailures.Delete(username)
	})

	encSecret, err := utils.ReversibleEncrypt("Secret123", testEncryptKey)
	require.NoError(t, err)
	dao := &daoMock.MetaDAO{}
	for _, tk := range tokens {
		dao.On("GetByUsername", mock.Anything, username).
			Return(&models.OIDCUser{ID: 3, UserID: 3, Secret: encSecret, Token: encryptToken(t, tk)}, nil).Once()
	}
	return &defaultManager{metaDao: dao}, dao
}

func expiredToken() *Token {
	return &Token{
		Token:      oauth2.Token{AccessToken: "old-access", RefreshToken: "old-refresh", Expiry: time.Now().Add(-time.Hour)},
		RawIDToken: "old-id-token",
	}
}

func refreshedToken(idToken string) *Token {
	return &Token{
		Token:      oauth2.Token{AccessToken: "new-access", RefreshToken: "new-refresh", Expiry: time.Now().Add(time.Hour)},
		RawIDToken: idToken,
	}
}

func storedToken(t *testing.T, dao *daoMock.MetaDAO) *Token {
	t.Helper()
	for _, call := range dao.Calls {
		if call.Method != "Update" {
			continue
		}
		tokenStr, err := utils.ReversibleDecrypt(call.Arguments.Get(1).(*models.OIDCUser).Token, testEncryptKey)
		require.NoError(t, err)
		tk := &Token{}
		require.NoError(t, json.Unmarshal([]byte(tokenStr), tk))
		return tk
	}
	t.Fatal("the refreshed token was not stored")
	return nil
}

func TestVerifySecretRefreshSucceeds(t *testing.T) {
	dm, dao := setupVerifySecret(t, "alice", expiredToken())
	dao.On("Update", mock.Anything, mock.Anything, "token").Return(nil)
	refreshTokenFn = func(context.Context, *Token) (*Token, error) { return refreshedToken("new-id-token"), nil }

	info, err := dm.VerifySecret(context.Background(), "alice", "Secret123")
	require.NoError(t, err)
	assert.Equal(t, "new-access", info.Subject)
	stored := storedToken(t, dao)
	assert.Equal(t, "new-refresh", stored.RefreshToken)
	assert.False(t, stored.IDTokenRetained)
}

func TestVerifySecretKeepsIDTokenWhenRefreshOmitsIt(t *testing.T) {
	dm, dao := setupVerifySecret(t, "bob", expiredToken())
	dao.On("Update", mock.Anything, mock.Anything, "token").Return(nil)
	refreshTokenFn = func(context.Context, *Token) (*Token, error) { return refreshedToken(""), nil }

	_, err := dm.VerifySecret(context.Background(), "bob", "Secret123")
	require.NoError(t, err)
	stored := storedToken(t, dao)
	assert.Equal(t, "old-id-token", stored.RawIDToken)
	assert.True(t, stored.IDTokenRetained)
}

func TestConsolidateUserInfoRejectsRetainedIDTokenClaims(t *testing.T) {
	local := &UserInfo{Username: "bob", Groups: []string{"harbor-admins"}, AdminGroupMember: true}
	_, err := consolidateUserInfo(&Token{RawIDToken: "old-id-token", IDTokenRetained: true}, local, nil)
	require.Error(t, err)

	// userinfo without a groups claim must not take the groups of the retained ID token
	remote := &UserInfo{Subject: "sub-bob", Username: "bob"}
	local = &UserInfo{Subject: "sub-bob", Username: "bob", Groups: []string{"harbor-admins"}, AdminGroupMember: true, hasGroupClaim: true}
	info, err := consolidateUserInfo(&Token{RawIDToken: "old-id-token", IDTokenRetained: true}, local, remote)
	require.NoError(t, err)
	assert.Empty(t, info.Groups)
	assert.False(t, info.AdminGroupMember)

	local = &UserInfo{Username: "bob", Groups: []string{"harbor-admins"}, AdminGroupMember: true}
	info, err = consolidateUserInfo(&Token{RawIDToken: "new-id-token"}, local, nil)
	require.NoError(t, err)
	assert.Equal(t, "bob", info.Username)
}

func TestVerifySecretRejectsOnInvalidGrant(t *testing.T) {
	// the second read returns the same token, nothing was rotated meanwhile
	dm, dao := setupVerifySecret(t, "carol", expiredToken(), expiredToken())
	refreshTokenFn = func(context.Context, *Token) (*Token, error) {
		return nil, &oauth2.RetrieveError{ErrorCode: "invalid_grant"}
	}

	_, err := dm.VerifySecret(context.Background(), "carol", "Secret123")
	var verr *SecretVerifyError
	require.ErrorAs(t, err, &verr)
	assert.True(t, IsRefreshFailure(err))
	dao.AssertNotCalled(t, "Update", mock.Anything, mock.Anything, mock.Anything)
	_, logged := refreshFailures.Load("carol")
	assert.True(t, logged)
}

func TestVerifySecretRejectsWhenIdPUnavailable(t *testing.T) {
	for name, refreshErr := range map[string]error{
		"server error": &oauth2.RetrieveError{Response: nil, ErrorCode: "server_error"},
		"timeout":      fmt.Errorf("dial tcp: i/o timeout"),
	} {
		t.Run(name, func(t *testing.T) {
			dm, dao := setupVerifySecret(t, "dave", expiredToken())
			refreshTokenFn = func(context.Context, *Token) (*Token, error) { return nil, refreshErr }

			_, err := dm.VerifySecret(context.Background(), "dave", "Secret123")
			var verr *SecretVerifyError
			require.ErrorAs(t, err, &verr)
			assert.True(t, IsRefreshFailure(err))
			// no re-read of the stored token, the IdP did not reject the refresh token
			dao.AssertNumberOfCalls(t, "GetByUsername", 1)
		})
	}
}

func TestVerifySecretUsesTokenRotatedByConcurrentRequest(t *testing.T) {
	dm, dao := setupVerifySecret(t, "erin", expiredToken(), refreshedToken("rotated-id-token"))
	refreshTokenFn = func(context.Context, *Token) (*Token, error) {
		return nil, &oauth2.RetrieveError{ErrorCode: "invalid_grant"}
	}

	info, err := dm.VerifySecret(context.Background(), "erin", "Secret123")
	require.NoError(t, err)
	assert.Equal(t, "new-access", info.Subject)
	dao.AssertNotCalled(t, "Update", mock.Anything, mock.Anything, mock.Anything)
}

func TestVerifySecretMismatchIsNotRefreshFailure(t *testing.T) {
	dm, _ := setupVerifySecret(t, "frank", expiredToken())
	_, err := dm.VerifySecret(context.Background(), "frank", "wrong")
	require.Error(t, err)
	assert.False(t, IsRefreshFailure(err))
}
