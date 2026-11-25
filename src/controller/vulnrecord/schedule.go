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

// Package vulnrecord schedules the daily cleanup of vulnerability records no scan report links to.
package vulnrecord

import (
	"context"

	"github.com/goharbor/harbor/src/jobservice/job"
	"github.com/goharbor/harbor/src/lib/log"
	"github.com/goharbor/harbor/src/lib/q"
	"github.com/goharbor/harbor/src/pkg/scheduler"
	"github.com/goharbor/harbor/src/pkg/task"
)

const (
	// CleanupCallback is the scheduler callback that starts the cleanup.
	CleanupCallback = "VULNERABILITY_RECORD_CLEANUP"
	cronTypeDaily   = "Daily"
	// Away from midnight, when most of Harbor's daily schedules fire.
	cronSpec = "0 30 3 * * *"
)

var (
	sched   = scheduler.Sched
	execMgr = task.ExecMgr
	taskMgr = task.Mgr
)

func init() {
	if err := scheduler.RegisterCallbackFunc(CleanupCallback, callback); err != nil {
		log.Fatalf("failed to register the callback for the vulnerability record cleanup schedule, error %v", err)
	}
}

func callback(ctx context.Context, _ string) error {
	return Start(ctx, task.ExecutionTriggerSchedule)
}

// Start runs the cleanup once.
func Start(ctx context.Context, trigger string) error {
	execID, err := execMgr.Create(ctx, job.VulnerabilityRecordCleanupVendorType, 0, trigger)
	if err != nil {
		return err
	}
	_, err = taskMgr.Create(ctx, execID, &task.Job{
		Name:     job.VulnerabilityRecordCleanupVendorType,
		Metadata: &job.Metadata{JobKind: job.KindGeneric},
	})
	if err != nil {
		if e := execMgr.MarkError(ctx, execID, err.Error()); e != nil {
			log.Errorf("failed to mark the vulnerability record cleanup execution %d as failed: %v", execID, e)
		}
		return err
	}
	return nil
}

// ScheduleCleanup creates the daily schedule unless it exists.
func ScheduleCleanup(ctx context.Context) error {
	schedules, err := sched.ListSchedules(ctx, q.New(q.KeyWords{"vendor_type": job.VulnerabilityRecordCleanupVendorType}))
	if err != nil {
		return err
	}
	if len(schedules) > 0 {
		return nil
	}
	id, err := sched.Schedule(ctx, job.VulnerabilityRecordCleanupVendorType, 0, cronTypeDaily, cronSpec, CleanupCallback, nil, nil)
	if err != nil {
		return err
	}
	log.Infof("Scheduled the vulnerability record cleanup with schedule id %d", id)
	return nil
}
