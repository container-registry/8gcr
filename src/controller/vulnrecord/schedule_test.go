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

package vulnrecord

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/goharbor/harbor/src/jobservice/job"
	"github.com/goharbor/harbor/src/pkg/scheduler"
	"github.com/goharbor/harbor/src/pkg/task"
	testingscheduler "github.com/goharbor/harbor/src/testing/pkg/scheduler"
	testingtask "github.com/goharbor/harbor/src/testing/pkg/task"
)

func withScheduler(t *testing.T) *testingscheduler.Scheduler {
	s := &testingscheduler.Scheduler{}
	old := sched
	sched = s
	t.Cleanup(func() { sched = old })
	return s
}

func withTaskManagers(t *testing.T) (*testingtask.ExecutionManager, *testingtask.Manager) {
	e, m := &testingtask.ExecutionManager{}, &testingtask.Manager{}
	oldE, oldM := execMgr, taskMgr
	execMgr, taskMgr = e, m
	t.Cleanup(func() { execMgr, taskMgr = oldE, oldM })
	return e, m
}

func TestScheduleCleanupCreatesTheDailySchedule(t *testing.T) {
	s := withScheduler(t)
	ctx := context.Background()
	s.On("ListSchedules", ctx, mock.Anything).Return(nil, nil).Once()
	s.On("Schedule", ctx, job.VulnerabilityRecordCleanupVendorType, int64(0), cronTypeDaily, cronSpec, CleanupCallback, nil, map[string]any(nil)).
		Return(int64(1), nil).Once()
	require.NoError(t, ScheduleCleanup(ctx))
	s.AssertExpectations(t)
}

// Core calls ScheduleCleanup on every start, so an existing schedule must not get a second one.
func TestScheduleCleanupKeepsAnExistingSchedule(t *testing.T) {
	s := withScheduler(t)
	ctx := context.Background()
	s.On("ListSchedules", ctx, mock.Anything).Return([]*scheduler.Schedule{{ID: 1}}, nil).Once()
	require.NoError(t, ScheduleCleanup(ctx))
	s.AssertNotCalled(t, "Schedule", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestScheduleCleanupReturnsTheListError(t *testing.T) {
	s := withScheduler(t)
	ctx := context.Background()
	s.On("ListSchedules", ctx, mock.Anything).Return(nil, errors.New("db down")).Once()
	require.Error(t, ScheduleCleanup(ctx))
	s.AssertNotCalled(t, "Schedule", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestStartSubmitsTheCleanupJob(t *testing.T) {
	e, m := withTaskManagers(t)
	ctx := context.Background()
	e.On("Create", ctx, job.VulnerabilityRecordCleanupVendorType, int64(0), task.ExecutionTriggerSchedule).Return(int64(7), nil).Once()
	m.On("Create", ctx, int64(7), mock.MatchedBy(func(j *task.Job) bool {
		return j.Name == job.VulnerabilityRecordCleanupVendorType && j.Metadata.JobKind == job.KindGeneric
	})).Return(int64(1), nil).Once()
	require.NoError(t, Start(ctx, task.ExecutionTriggerSchedule))
	e.AssertExpectations(t)
	m.AssertExpectations(t)
}

func TestStartMarksTheExecutionFailedWhenTheTaskCannotBeCreated(t *testing.T) {
	e, m := withTaskManagers(t)
	ctx := context.Background()
	e.On("Create", ctx, job.VulnerabilityRecordCleanupVendorType, int64(0), task.ExecutionTriggerManual).Return(int64(7), nil).Once()
	m.On("Create", ctx, int64(7), mock.Anything).Return(int64(0), errors.New("jobservice down")).Once()
	e.On("MarkError", ctx, int64(7), "jobservice down").Return(nil).Once()
	require.Error(t, Start(ctx, task.ExecutionTriggerManual))
	e.AssertExpectations(t)
}
