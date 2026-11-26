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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/goharbor/harbor/src/controller/event"
	"github.com/goharbor/harbor/src/pkg/auditext/collapse"
)

func TestSkippedPullIsNotAudited(t *testing.T) {
	mgr := mockManager(t)
	ctx := collapse.NewRequestMarks().Into(context.Background())
	collapse.SkipPullAudit(ctx)
	pull := &event.PullArtifactEvent{ArtifactEvent: artifactEvent("lib/app", "sha256:child")}
	assert.NoError(t, (&Handler{}).Handle(ctx, pull))
	mgr.AssertNotCalled(t, "Create", mock.Anything, mock.Anything)
}

func TestPullIsAudited(t *testing.T) {
	mgr := mockManager(t)
	mgr.On("Create", mock.Anything, mock.Anything).Return(int64(1), nil)
	ctx := collapse.NewRequestMarks().Into(context.Background())
	pull := &event.PullArtifactEvent{ArtifactEvent: artifactEvent("lib/app", "sha256:index")}
	assert.NoError(t, (&Handler{}).Handle(ctx, pull))
	mgr.AssertNumberOfCalls(t, "Create", 1)
}
