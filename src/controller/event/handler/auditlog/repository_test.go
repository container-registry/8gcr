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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/goharbor/harbor/src/controller/event"
	"github.com/goharbor/harbor/src/pkg/auditext/collapse"
)

func TestArtifactsOfADeletedRepositoryAreCovered(t *testing.T) {
	mgr := mockManager(t)
	h := &Handler{}
	mgr.On("Create", mock.Anything, mock.Anything).Return(int64(1), nil)
	ctx := collapse.WithDeletedRepositories(context.Background(), []string{"lib/gone"})
	del := &event.DeleteArtifactEvent{ArtifactEvent: artifactEvent("lib/gone", "sha256:g")}
	assert.NoError(t, h.Handle(ctx, del))
	mgr.AssertNotCalled(t, "Create", mock.Anything, mock.Anything)

	assert.NoError(t, h.Handle(ctx, &event.DeleteRepositoryEvent{Repository: "lib/gone", Operator: "admin", OccurAt: time.Now()}))
	mgr.AssertNumberOfCalls(t, "Create", 1)
}

func TestArtifactsAreAuditedWhenRepositoryDeleteIsNot(t *testing.T) {
	mgr := mockManager(t)
	h := &Handler{}
	mgr.On("Create", mock.Anything, mock.Anything).Return(int64(1), nil)
	h.eventEnabled = func(_ context.Context, event string) bool { return event != "delete_repository" }
	ctx := collapse.WithDeletedRepositories(context.Background(), []string{"lib/gone"})
	del := &event.DeleteArtifactEvent{ArtifactEvent: artifactEvent("lib/gone", "sha256:g")}
	assert.NoError(t, h.Handle(ctx, del))
	mgr.AssertNumberOfCalls(t, "Create", 1)
}
