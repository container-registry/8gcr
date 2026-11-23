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

	"github.com/goharbor/harbor/src/common"
	"github.com/goharbor/harbor/src/controller/event"
	"github.com/goharbor/harbor/src/lib/config"
	"github.com/goharbor/harbor/src/lib/errors"
	"github.com/goharbor/harbor/src/pkg/auditext/collapse"
	am "github.com/goharbor/harbor/src/pkg/auditext/model"
	"github.com/goharbor/harbor/src/pkg/robot"
	robotModel "github.com/goharbor/harbor/src/pkg/robot/model"
	v1 "github.com/goharbor/harbor/src/pkg/scan/rest/v1"
	"github.com/goharbor/harbor/src/pkg/user"
	testingrobot "github.com/goharbor/harbor/src/testing/pkg/robot"
	testinguser "github.com/goharbor/harbor/src/testing/pkg/user"
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

func TestScanIsOneRow(t *testing.T) {
	mgr := mockManager(t)
	mgr.On("Create", mock.Anything, mock.Anything).Return(int64(1), nil)
	robots := &testingrobot.Manager{}
	orig := robot.Mgr
	robot.Mgr = robots
	t.Cleanup(func() { robot.Mgr = orig })
	robots.On("List", mock.Anything, mock.Anything).Return([]*robotModel.Robot{{Name: "lib+scanner-Trivy-0d3c"}}, nil).Once()
	robots.On("List", mock.Anything, mock.Anything).Return([]*robotModel.Robot{{Name: "lib+scanner-ci", Visible: true}}, nil).Once()

	scanner := &robotModel.Robot{Name: "robot$lib+scanner-Trivy-0d3c"}
	h, ctx := &Handler{}, context.Background()
	assert.NoError(t, h.Handle(ctx, &event.CreateRobotEvent{Robot: scanner}))
	assert.NoError(t, h.Handle(ctx, &event.DeleteRobotEvent{Robot: scanner}))
	pullAs := func(operator string) {
		pull := &event.PullArtifactEvent{ArtifactEvent: artifactEvent("lib/app", "sha256:a")}
		pull.Operator = operator
		assert.NoError(t, h.Handle(ctx, pull))
	}
	pullAs("robot$lib+scanner-Trivy-0d3c")
	mgr.AssertNotCalled(t, "Create", mock.Anything, mock.Anything)
	scan := &event.ScanImageEvent{EventType: event.TopicScanningCompleted, Operator: "admin", Scanner: "Trivy",
		Artifact: &v1.Artifact{NamespaceID: 1, Repository: "lib/app", Digest: "sha256:a", Tag: "v1"}}
	assert.NoError(t, h.Handle(ctx, scan))
	mgr.AssertCalled(t, "Create", mock.Anything, mock.MatchedBy(func(a *am.AuditLogExt) bool {
		return a.OperationDescription == "admin scanned artifact lib/app@sha256:a (Trivy)"
	}))

	assert.NoError(t, h.Handle(ctx, &event.CreateRobotEvent{Robot: &robotModel.Robot{Name: "robot$lib+ci", Visible: true}}))
	pullAs("robot$lib+scanner-ci") // visible robot named like a scanner
	pullAs("alice")
	mgr.AssertNumberOfCalls(t, "Create", 4)
	robots.AssertNumberOfCalls(t, "List", 2)
}

func TestScanByUserDeletedMeanwhileIsMasked(t *testing.T) {
	mgr := mockManager(t)
	mgr.On("Create", mock.Anything, mock.Anything).Return(int64(1), nil)
	config.InitWithSettings(map[string]any{common.RobotScannerNamePrefix: "scanner", common.RobotNamePrefix: "robot$", common.GDPRAuditLogs: true})
	t.Cleanup(func() {
		config.InitWithSettings(map[string]any{common.RobotScannerNamePrefix: "scanner", common.RobotNamePrefix: "robot$"})
	})
	users := &testinguser.Manager{}
	orig := user.Mgr
	user.Mgr = users
	t.Cleanup(func() { user.Mgr = orig })
	robots := &testingrobot.Manager{}
	origRobots := robot.Mgr
	robot.Mgr = robots
	t.Cleanup(func() { robot.Mgr = origRobots })
	users.On("GetByName", mock.Anything, mock.Anything).Return(nil, errors.NotFoundError(nil))
	users.On("GenerateCheckSum", mock.Anything).Return("8a7c")
	robots.On("List", mock.Anything, mock.Anything).Return(nil, nil) // robot$bob is a deleted human, no robot

	for _, name := range []string{"bob", "robot$bob"} {
		scan := &event.ScanImageEvent{EventType: event.TopicScanningCompleted, Operator: name, Scanner: "Trivy",
			Artifact: &v1.Artifact{Repository: "lib/app", Digest: "sha256:a"}}
		assert.NoError(t, (&Handler{}).Handle(context.Background(), scan))
	}
	mgr.AssertNumberOfCalls(t, "Create", 2)
	for _, c := range mgr.Calls {
		assert.Equal(t, "8a7c scanned artifact lib/app@sha256:a (Trivy)", c.Arguments.Get(1).(*am.AuditLogExt).OperationDescription)
	}

	scheduled := &event.ScanImageEvent{EventType: event.TopicScanningCompleted, Operator: "harbor-jobservice", Scheduled: true,
		Artifact: &v1.Artifact{Repository: "lib/app", Digest: "sha256:a"}}
	assert.NoError(t, (&Handler{}).Handle(context.Background(), scheduled))
	mgr.AssertCalled(t, "Create", mock.Anything, mock.MatchedBy(func(a *am.AuditLogExt) bool { return a.Username == "harbor-jobservice" }))
}
