package controllers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/goharbor/harbor/src/common/models"
	ctluser "github.com/goharbor/harbor/src/controller/user"
	"github.com/goharbor/harbor/src/lib/config"
	"github.com/goharbor/harbor/src/lib/encrypt"
	"github.com/goharbor/harbor/src/lib/errors"
	_ "github.com/goharbor/harbor/src/pkg/config/inmemory"
	"github.com/goharbor/harbor/src/pkg/oidc"
	testingUser "github.com/goharbor/harbor/src/testing/controller/user"
)

// withUserCtl swaps the global user controller for a mock and restores it after the test.
// It also initialises config with a fixed key, which secretAndToken needs.
func withUserCtl(t *testing.T) *testingUser.Controller {
	t.Helper()
	config.InitWithSettings(nil, &encrypt.PresetKeyProvider{Key: "naa4JtarA1Zsc3uY"})
	orig := ctluser.Ctl
	t.Cleanup(func() { ctluser.Ctl = orig })
	testCtl := &testingUser.Controller{}
	ctluser.Ctl = testCtl
	return testCtl
}

// unlinkedIdentity returns an identity whose email the IdP has verified.
func unlinkedIdentity(email, username string) *oidc.UserInfo {
	return &oidc.UserInfo{
		Subject:       "new-sub",
		Issuer:        "https://idp.example.com",
		Username:      username,
		Email:         email,
		EmailVerified: true,
	}
}

// An unverified email must never be used to find or link a local account, even when it matches exactly.
func TestResolveOIDCUserIgnoresUnverifiedEmail(t *testing.T) {
	testCtl := withUserCtl(t)
	notFoundSubIss(testCtl)
	testCtl.On("GetByName", mock.Anything, "dave").Return(nil, errors.NotFoundError(nil))

	info := unlinkedIdentity("admin@example.com", "dave")
	info.EmailVerified = false
	u, err := resolveOIDCUser(context.Background(), info, []byte(`{}`))
	require.Error(t, err)
	assert.Nil(t, u)
	testCtl.AssertNotCalled(t, "GetByEmail", mock.Anything, mock.Anything)
	testCtl.AssertNotCalled(t, "LinkExistingUserToOIDC", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func notFoundSubIss(testCtl *testingUser.Controller) {
	testCtl.On("GetBySubIss", mock.Anything, "new-sub", "https://idp.example.com").
		Return(nil, errors.NotFoundError(nil))
}

// An unlinked identity whose email exactly matches an unlinked local account links to it.
func TestResolveOIDCUserLinksByEmail(t *testing.T) {
	testCtl := withUserCtl(t)
	notFoundSubIss(testCtl)
	testCtl.On("GetByEmail", mock.Anything, "alice@example.com").
		Return(&models.User{UserID: 7, Username: "alice", Email: "alice@example.com"}, nil)
	testCtl.On("GetByName", mock.Anything, "alice-idp").Return(nil, errors.NotFoundError(nil))
	testCtl.On("HasOIDCIdentity", mock.Anything, 7).Return(false, nil)
	testCtl.On("LinkExistingUserToOIDC", mock.Anything, 7, "new-sub", "https://idp.example.com", mock.Anything, mock.Anything).
		Return(nil)
	testCtl.On("Get", mock.Anything, 7, mock.Anything).
		Return(&models.User{UserID: 7, Username: "alice"}, nil)

	u, err := resolveOIDCUser(context.Background(), unlinkedIdentity("alice@example.com", "alice-idp"), []byte(`{}`))
	require.NoError(t, err)
	assert.Equal(t, 7, u.UserID)
	testCtl.AssertCalled(t, "LinkExistingUserToOIDC", mock.Anything, 7, "new-sub", "https://idp.example.com", mock.Anything, mock.Anything)
}

// An unlinked identity whose login name matches an unlinked local account links to it.
func TestResolveOIDCUserLinksByLoginName(t *testing.T) {
	testCtl := withUserCtl(t)
	notFoundSubIss(testCtl)
	testCtl.On("GetByEmail", mock.Anything, "bob@idp.example.com").Return(nil, errors.NotFoundError(nil))
	testCtl.On("GetByName", mock.Anything, "bob").
		Return(&models.User{UserID: 9, Username: "bob"}, nil)
	testCtl.On("HasOIDCIdentity", mock.Anything, 9).Return(false, nil)
	testCtl.On("LinkExistingUserToOIDC", mock.Anything, 9, "new-sub", "https://idp.example.com", mock.Anything, mock.Anything).
		Return(nil)
	testCtl.On("Get", mock.Anything, 9, mock.Anything).
		Return(&models.User{UserID: 9, Username: "bob"}, nil)

	u, err := resolveOIDCUser(context.Background(), unlinkedIdentity("bob@idp.example.com", "bob"), []byte(`{}`))
	require.NoError(t, err)
	assert.Equal(t, 9, u.UserID)
	testCtl.AssertCalled(t, "LinkExistingUserToOIDC", mock.Anything, 9, "new-sub", "https://idp.example.com", mock.Anything, mock.Anything)
}

// Email and login name matching two different accounts must not link either of them.
func TestResolveOIDCUserRefusesAmbiguousMatch(t *testing.T) {
	testCtl := withUserCtl(t)
	notFoundSubIss(testCtl)
	testCtl.On("GetByEmail", mock.Anything, "admin@example.com").
		Return(&models.User{UserID: 1, Username: "admin", Email: "admin@example.com"}, nil)
	testCtl.On("GetByName", mock.Anything, "carol").
		Return(&models.User{UserID: 2, Username: "carol"}, nil)

	u, err := resolveOIDCUser(context.Background(), unlinkedIdentity("admin@example.com", "carol"), []byte(`{}`))
	require.Error(t, err)
	assert.Nil(t, u)
	assert.True(t, errors.IsErr(err, errors.ForbiddenCode))
	testCtl.AssertNotCalled(t, "LinkExistingUserToOIDC", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	testCtl.AssertNotCalled(t, "OnboardOIDCUser", mock.Anything, mock.Anything)
}

// A matching account that already has an OIDC identity must not gain a second one.
func TestResolveOIDCUserRefusesAccountAlreadyLinked(t *testing.T) {
	testCtl := withUserCtl(t)
	notFoundSubIss(testCtl)
	testCtl.On("GetByEmail", mock.Anything, "admin@example.com").
		Return(&models.User{UserID: 1, Username: "admin", Email: "admin@example.com"}, nil)
	testCtl.On("GetByName", mock.Anything, "attacker").Return(nil, errors.NotFoundError(nil))
	testCtl.On("HasOIDCIdentity", mock.Anything, 1).Return(true, nil)

	u, err := resolveOIDCUser(context.Background(), unlinkedIdentity("admin@example.com", "attacker"), []byte(`{}`))
	require.Error(t, err)
	assert.Nil(t, u)
	assert.True(t, errors.IsErr(err, errors.ForbiddenCode))
	testCtl.AssertNotCalled(t, "LinkExistingUserToOIDC", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}
