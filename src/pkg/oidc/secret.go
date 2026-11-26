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
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"golang.org/x/oauth2"

	"github.com/goharbor/harbor/src/common/utils"
	"github.com/goharbor/harbor/src/lib/config"
	"github.com/goharbor/harbor/src/lib/log"
	"github.com/goharbor/harbor/src/pkg/oidc/dao"
)

// SecretVerifyError wraps the different errors happened when verifying a secret for OIDC user.  When seeing this error,
// the caller should consider this an authentication error.
type SecretVerifyError struct {
	cause error
}

func (se *SecretVerifyError) Error() string {
	return fmt.Sprintf("failed to verify the secret: %v", se.cause)
}

func (se *SecretVerifyError) Unwrap() error {
	return se.cause
}

func verifyError(err error) error {
	return &SecretVerifyError{err}
}

var errRefreshFailed = errors.New("failed to refresh token")

// IsRefreshFailure reports whether the secret was rejected because its token could not be refreshed, that
// failure is already logged once per user by VerifySecret.
func IsRefreshFailure(err error) bool {
	return errors.Is(err, errRefreshFailed)
}

// SecretManager is the interface for store and verify the secret
type SecretManager interface {
	// VerifySecret verifies the secret and the token associated with it, it refreshes the token in the DB if it's
	// refreshed during the verification.
	VerifySecret(ctx context.Context, username string, secret string) (*UserInfo, error)
}

type keyGetter struct {
	sync.RWMutex
	key string
}

func (kg *keyGetter) encryptKey() (string, error) {
	kg.RLock()
	if kg.key == "" {
		kg.RUnlock()
		kg.Lock()
		defer kg.Unlock()
		if kg.key == "" {
			k, err := config.SecretKey()
			if err != nil {
				return "", err
			}
			kg.key = k
		}
	} else {
		defer kg.RUnlock()
	}
	return kg.key, nil
}

var keyLoader = &keyGetter{}

type defaultManager struct {
	metaDao dao.MetaDAO
}

var m SecretManager = &defaultManager{
	metaDao: dao.NewMetaDao(),
}

// VerifySecret verifies the secret and the token associated with it, it refreshes the token in the DB if it's
// refreshed during the verification.  It returns a populated user model based on the ID token associated with the secret.
func (dm *defaultManager) VerifySecret(ctx context.Context, username string, secret string) (*UserInfo, error) {
	log.Debugf("Verifying the secret for user: %s", username)
	oidcUser, err := dm.metaDao.GetByUsername(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("failed to get oidc user info, error: %v", err)
	}
	if oidcUser == nil {
		return nil, fmt.Errorf("user is not onboarded as OIDC user, username: %s", username)
	}
	key, err := keyLoader.encryptKey()
	if err != nil {
		return nil, fmt.Errorf("failed to load the key for encryption/decryption： %v", err)
	}
	plainSecret, err := utils.ReversibleDecrypt(oidcUser.Secret, key)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt secret from DB: %v", err)
	}
	if subtle.ConstantTimeCompare([]byte(secret), []byte(plainSecret)) != 1 {
		return nil, verifyError(fmt.Errorf("secret mismatch, username: %s", username))
	}
	tokenStr, err := utils.ReversibleDecrypt(oidcUser.Token, key)
	if err != nil {
		return nil, verifyError(err)
	}
	token := &Token{}
	err = json.Unmarshal(([]byte)(tokenStr), token)
	if err != nil {
		return nil, verifyError(err)
	}
	if !token.Valid() {
		log.Debug("Refreshing token")
		refreshed, err := refreshTokenFn(ctx, token)
		if err != nil {
			warnRefreshFailure(username, err)
			// a concurrent request may have rotated the refresh token already, use the token it stored
			rotated := dm.rotatedToken(ctx, username, oidcUser.Token, key, err)
			if rotated == nil {
				return nil, verifyError(fmt.Errorf("%w, username: %s, error: %v", errRefreshFailed, username, err))
			}
			refreshed = rotated
		} else {
			refreshFailures.Delete(username)
			// a refresh response may omit the ID token, keep the previous one
			if refreshed.RawIDToken == "" {
				refreshed.RawIDToken, refreshed.IDTokenRetained = token.RawIDToken, true
			}
			tb, err := json.Marshal(refreshed)
			if err != nil {
				return nil, fmt.Errorf("failed to encode the refreshed token, error: %v", err)
			}
			encToken, _ := utils.ReversibleEncrypt(string(tb), key)
			oidcUser.Token = encToken
			// only updates the token column of the record
			if err := dm.metaDao.Update(ctx, oidcUser, "token"); err != nil {
				log.Errorf("Failed to persist token, user id: %d, error: %v", oidcUser.UserID, err)
			}
			log.Debug("Token refreshed and persisted")
		}
		token = refreshed
	}
	info, err := userInfoFromTokenFn(ctx, token)
	if err != nil {
		return nil, verifyError(err)
	}
	return info, nil
}

// rotatedToken re-reads the stored token after an invalid_grant refresh error and returns it when another
// request has stored a newer, valid token meanwhile.
func (dm *defaultManager) rotatedToken(ctx context.Context, username, oldToken, key string, refreshErr error) *Token {
	var re *oauth2.RetrieveError
	if !errors.As(refreshErr, &re) || re.ErrorCode != "invalid_grant" {
		return nil
	}
	u, err := dm.metaDao.GetByUsername(ctx, username)
	if err != nil || u == nil || u.Token == oldToken {
		return nil
	}
	tokenStr, err := utils.ReversibleDecrypt(u.Token, key)
	if err != nil {
		return nil
	}
	t := &Token{}
	if err := json.Unmarshal([]byte(tokenStr), t); err != nil || !t.Valid() {
		return nil
	}
	return t
}

var (
	refreshTokenFn      = refreshToken
	userInfoFromTokenFn = UserInfoFromToken
	// refreshFailures records the users whose token refresh failed, so the failure is logged once per user
	// instead of once per request.  An entry is removed when a refresh for that user succeeds.
	refreshFailures sync.Map
)

func warnRefreshFailure(username string, err error) {
	if _, logged := refreshFailures.LoadOrStore(username, struct{}{}); logged {
		log.Debugf("Failed to refresh the OIDC token, username: %s, error: %v", username, err)
		return
	}
	log.Warningf("Failed to refresh the OIDC token, the CLI secret is rejected until a refresh succeeds, username: %s, error: %v", username, err)
}

// VerifySecret calls the manager to verify the secret.
func VerifySecret(ctx context.Context, name string, secret string) (*UserInfo, error) {
	return m.VerifySecret(ctx, name, secret)
}
