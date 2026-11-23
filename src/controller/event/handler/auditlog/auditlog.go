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

package auditlog

import (
	"context"
	"fmt"
	"strings"

	"github.com/goharbor/harbor/src/common"
	"github.com/goharbor/harbor/src/controller/event"
	evtModel "github.com/goharbor/harbor/src/controller/event/model"
	"github.com/goharbor/harbor/src/lib/config"
	"github.com/goharbor/harbor/src/lib/errors"
	"github.com/goharbor/harbor/src/lib/log"
	"github.com/goharbor/harbor/src/lib/q"
	"github.com/goharbor/harbor/src/pkg/auditext"
	"github.com/goharbor/harbor/src/pkg/auditext/collapse"
	am "github.com/goharbor/harbor/src/pkg/auditext/model"
	"github.com/goharbor/harbor/src/pkg/auditext/summary"
	"github.com/goharbor/harbor/src/pkg/robot"
	"github.com/goharbor/harbor/src/pkg/user"
)

// Handler - audit log handler
type Handler struct {
}

// AuditResolver - interface to resolve to AuditLog
type AuditResolver interface {
	ResolveToAuditLog() (*am.AuditLogExt, error)
}

// Name ...
func (h *Handler) Name() string {
	return "AuditLog"
}

// Handle ...
func (h *Handler) Handle(ctx context.Context, value any) error {
	var addAuditLog bool
	switch v := value.(type) {
	case *event.PushArtifactEvent, *event.DeleteArtifactEvent,
		*event.DeleteRepositoryEvent, *event.CreateProjectEvent, *event.DeleteProjectEvent,
		*event.DeleteTagEvent, *event.CreateTagEvent, *evtModel.CommonEvent,
		*event.ScanImageEvent:
		addAuditLog = true
	case *event.CreateRobotEvent: // API robots are visible, only scan jobs create hidden ones
		addAuditLog = v.Robot.Visible
	case *event.DeleteRobotEvent:
		addAuditLog = v.Robot.Visible
	case *event.PullArtifactEvent:
		addAuditLog = !config.PullAuditLogDisable(ctx) && !collapse.PullAuditSkipped(ctx) && !isScanPull(ctx, v)
	default:
		log.Errorf("Can not handler this event type! %#v", v)
	}

	if addAuditLog {
		resolver := value.(AuditResolver)
		auditLog, err := resolver.ResolveToAuditLog()
		if err != nil {
			log.Errorf("failed to handler event %v", err)
			return err
		}
		if auditLog != nil && config.AuditLogEventEnabled(ctx, fmt.Sprintf("%v_%v", auditLog.Operation, auditLog.ResourceType)) {
			if scan, ok := value.(*event.ScanImageEvent); ok && scan.Operator != "" && !scan.Scheduled {
				maskDeletedUser(ctx, auditLog)
			}
			auditLog.OperationDescription = summary.Describe(auditLog)
			_, err := auditext.Mgr.Create(ctx, auditLog)
			if err != nil {
				log.Infof("add audit log err: %v", err)
			}
		}
	}
	return nil
}

// isScanPull reports a pull by the hidden robot of a scan job, named like upstream's isScannerUser.
func isScanPull(ctx context.Context, e *event.PullArtifactEvent) bool {
	project, _, _ := strings.Cut(e.Repository, "/")
	name, ok := strings.CutPrefix(e.Operator, config.RobotPrefix(ctx))
	if !ok || !strings.HasPrefix(name, project+"+"+config.ScannerRobotPrefix(ctx)) {
		return false
	}
	robots, err := robot.Mgr.List(ctx, q.New(q.KeyWords{"name": name}))
	return err == nil && len(robots) == 1 && !robots[0].Visible
}

// maskDeletedUser masks a scan's user deleted before the scan ended, as the GDPR job masked their older rows.
func maskDeletedUser(ctx context.Context, a *am.AuditLogExt) {
	if !config.DefaultMgr().Get(ctx, common.GDPRAuditLogs).GetBool() {
		return
	}
	if _, err := user.Mgr.GetByName(ctx, a.Username); !errors.IsNotFoundErr(err) {
		return
	}
	if name, ok := strings.CutPrefix(a.Username, config.RobotPrefix(ctx)); ok {
		if robots, err := robot.Mgr.List(ctx, q.New(q.KeyWords{"name": name})); err == nil && len(robots) > 0 {
			return
		}
	}
	a.Username = user.Mgr.GenerateCheckSum(a.Username)
}

// IsStateful ...
func (h *Handler) IsStateful() bool {
	return false
}
