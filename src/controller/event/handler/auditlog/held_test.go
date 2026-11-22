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

//go:build !db

package auditlog

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/goharbor/harbor/src/controller/event"
	"github.com/goharbor/harbor/src/lib/errors"
	"github.com/goharbor/harbor/src/pkg/auditext/collapse"
	am "github.com/goharbor/harbor/src/pkg/auditext/model"
	_ "github.com/goharbor/harbor/src/pkg/config/inmemory"
	"github.com/goharbor/harbor/src/pkg/user"
	testingauditext "github.com/goharbor/harbor/src/testing/pkg/auditext"
)

// withMockManager returns a handler with its own mock manager and held set,
// so nothing here touches package state other tests' handlers read.
func withMockManager(t *testing.T) (*Handler, *testingauditext.Manager) {
	t.Helper()
	mgr := &testingauditext.Manager{}
	h := &Handler{held: newHeldPushes(mgr)}
	t.Cleanup(h.held.stop)
	return h, mgr
}

func pushEvent(repo, digest string, tags ...string) *event.PushArtifactEvent {
	e := artifactEvent(repo, digest)
	e.Tags = tags
	return &event.PushArtifactEvent{ArtifactEvent: e}
}

func TestHeldPushDroppedWhenAnIndexListsIt(t *testing.T) {
	h, mgr := withMockManager(t)
	h.held.holdFor = time.Hour

	assert.NoError(t, h.Handle(context.Background(), pushEvent("lib/held", "sha256:child")))
	collapse.MarkIndexMembers("lib/held", "alice", []byte(`{"manifests":[{"digest":"sha256:child"}]}`))
	h.held.flush()
	mgr.AssertNotCalled(t, "Create", mock.Anything, mock.Anything)
}

func TestHeldIndexDroppedWhenAParentIndexListsIt(t *testing.T) {
	h, mgr := withMockManager(t)
	h.held.holdFor = time.Hour
	child := pushEvent("lib/nested", "sha256:childindex")
	child.Artifact.ManifestMediaType = "application/vnd.oci.image.index.v1+json"

	assert.NoError(t, h.Handle(context.Background(), child))
	collapse.MarkIndexMembers("lib/nested", "alice", []byte(`{"manifests":[{"digest":"sha256:childindex"}]}`))
	h.held.flush()
	mgr.AssertNotCalled(t, "Create", mock.Anything, mock.Anything)
}

func TestHeldPushesAreCapped(t *testing.T) {
	h, mgr := withMockManager(t)
	mgr.On("Create", mock.Anything, mock.Anything).Return(int64(1), nil)
	h.held.holdFor = time.Hour
	for i := range maxHeldPushes + 3 {
		assert.NoError(t, h.Handle(context.Background(), pushEvent("lib/many", fmt.Sprintf("sha256:%d", i))))
	}
	mgr.AssertNumberOfCalls(t, "Create", 3)

	// a retry of a held digest stays one push even when the set is full
	assert.NoError(t, h.Handle(context.Background(), pushEvent("lib/many", "sha256:0")))
	mgr.AssertNumberOfCalls(t, "Create", 3)
}

func TestRepeatedPutOfAHeldDigestIsOnePush(t *testing.T) {
	h, mgr := withMockManager(t)
	mgr.On("Create", mock.Anything, mock.Anything).Return(int64(1), nil)
	h.held.holdFor = time.Hour
	for range 5 {
		assert.NoError(t, h.Handle(context.Background(), pushEvent("lib/retry", "sha256:same")))
	}
	assert.NoError(t, h.Handle(context.Background(), pushEvent("lib/retry", "sha256:other")))
	h.held.flush()
	mgr.AssertNumberOfCalls(t, "Create", 2)
}

func TestHeldPushAfterReleaseIsHeldAgain(t *testing.T) {
	h, mgr := withMockManager(t)
	written := make(chan struct{}, 2)
	mgr.On("Create", mock.Anything, mock.Anything).Run(func(mock.Arguments) { written <- struct{}{} }).Return(int64(1), nil)
	h.held.holdFor = 10 * time.Millisecond
	for range 2 {
		assert.NoError(t, h.Handle(context.Background(), pushEvent("lib/again", "sha256:a")))
		select {
		case <-written:
		case <-time.After(2 * time.Second):
			t.Fatal("held push never written")
		}
	}
}

func TestGDPRMasking(t *testing.T) {
	ctx := context.Background()
	found := func(context.Context) error { return nil }
	missing := func(context.Context) error { return errors.NotFoundError(nil) }
	broken := func(context.Context) error { return errors.New("connection refused") }
	robot := func(context.Context) bool { return true }
	notRobot := func(context.Context) bool { return false }
	assert.False(t, gdprMasked(ctx, "alice", true, found, notRobot), "existing user")
	assert.True(t, gdprMasked(ctx, "alice", true, missing, notRobot), "deleted user")
	assert.True(t, gdprMasked(ctx, "alice", true, broken, robot), "a failed lookup masks")
	assert.False(t, gdprMasked(ctx, "alice", false, missing, notRobot), "GDPR masking off")
	assert.False(t, gdprMasked(ctx, "robot$ci", true, missing, robot), "an existing robot is not a user")
}

func TestHeldPushOfADeletedUserIsMasked(t *testing.T) {
	h, mgr := withMockManager(t)
	written := make(chan *am.AuditLogExt, 1)
	mgr.On("Create", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		written <- args.Get(1).(*am.AuditLogExt)
	}).Return(int64(1), nil)
	h.held.holdFor = time.Hour
	h.held.deleted = func(_ context.Context, username string) bool { return username == "alice" }

	assert.NoError(t, h.Handle(context.Background(), pushEvent("lib/gdpr", "sha256:g")))
	h.held.flush()
	l := <-written
	masked := user.Mgr.GenerateCheckSum("alice")
	assert.Equal(t, masked, l.Username)
	assert.NotContains(t, l.OperationDescription, "alice")
}

func TestReplaceActor(t *testing.T) {
	assert.Equal(t, "1a2b3c4d pushed artifact alice/app@sha256:x", replaceActor("alice pushed artifact alice/app@sha256:x", "alice", "1a2b3c4d"))
	assert.Equal(t, "push artifact: alice/app", replaceActor("push artifact: alice/app", "alice", "1a2b3c4d"), "no leading actor")
	long := replaceActor("bob "+strings.Repeat("x", 1020), "bob", "8a7c1e2f")
	assert.Equal(t, opDescWidth, utf8.RuneCountInString(long), "the masked description still fits the column")
}

func TestHeldPushWrittenWhenNoIndexComes(t *testing.T) {
	h, mgr := withMockManager(t)
	written := make(chan *am.AuditLogExt, 1)
	mgr.On("Create", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		written <- args.Get(1).(*am.AuditLogExt)
	}).Return(int64(1), nil)
	h.held.holdFor = 20 * time.Millisecond

	assert.NoError(t, h.Handle(context.Background(), pushEvent("lib/lonely", "sha256:solo")))
	select {
	case l := <-written:
		assert.Equal(t, "alice", l.Username)
		assert.Equal(t, "lib/lonely@sha256:solo", l.Resource)
	case <-time.After(2 * time.Second):
		t.Fatal("held push never written")
	}
}

func TestFlushWritesHeldPushes(t *testing.T) {
	h, mgr := withMockManager(t)
	mgr.On("Create", mock.Anything, mock.Anything).Return(int64(1), nil)
	h.held.holdFor = time.Hour

	assert.NoError(t, h.Handle(context.Background(), pushEvent("lib/flush", "sha256:f")))
	mgr.AssertNotCalled(t, "Create", mock.Anything, mock.Anything)
	h.held.flush()
	mgr.AssertNumberOfCalls(t, "Create", 1)
	h.held.flush()
	mgr.AssertNumberOfCalls(t, "Create", 1)
}

func TestTaggedPushIsWrittenAtOnce(t *testing.T) {
	h, mgr := withMockManager(t)
	mgr.On("Create", mock.Anything, mock.Anything).Return(int64(1), nil)
	assert.NoError(t, h.Handle(context.Background(), pushEvent("lib/tagged", "sha256:t", "1.0")))
	mgr.AssertNumberOfCalls(t, "Create", 1)
}

func TestHeldPushNotCoveredByAnotherUsersOrAnOlderIndex(t *testing.T) {
	h, mgr := withMockManager(t)
	mgr.On("Create", mock.Anything, mock.Anything).Return(int64(1), nil)
	h.held.holdFor = time.Hour

	collapse.MarkIndexMembers("lib/shared", "alice", []byte(`{"manifests":[{"digest":"sha256:x"}]}`))
	bob := pushEvent("lib/shared", "sha256:x")
	bob.Operator = "bob"
	assert.NoError(t, h.Handle(context.Background(), bob))
	later := pushEvent("lib/shared", "sha256:x")
	later.OccurAt = time.Now().Add(time.Second)
	assert.NoError(t, h.Handle(context.Background(), later))
	h.held.flush()
	mgr.AssertNumberOfCalls(t, "Create", 2)
}

func TestPushAfterFlushIsWrittenAtOnce(t *testing.T) {
	h, mgr := withMockManager(t)
	mgr.On("Create", mock.Anything, mock.Anything).Return(int64(1), nil)
	h.held.flush()
	assert.NoError(t, h.Handle(context.Background(), pushEvent("lib/late", "sha256:l")))
	mgr.AssertNumberOfCalls(t, "Create", 1)
}
