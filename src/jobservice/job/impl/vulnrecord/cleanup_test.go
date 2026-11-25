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

	"github.com/stretchr/testify/require"

	"github.com/goharbor/harbor/src/jobservice/job"
	"github.com/goharbor/harbor/src/pkg/scan/dao/scan"
	mockjobservice "github.com/goharbor/harbor/src/testing/jobservice"
)

type batchCall struct {
	afterID int64
	limit   int
}

// fakeDao answers DeleteUnlinked with scripted batches and records the cursor of every call.
type fakeDao struct {
	scan.VulnerabilityRecordDao
	batches [][2]int64 // deleted, last id looked at
	err     error
	calls   []batchCall
}

func (f *fakeDao) DeleteUnlinked(_ context.Context, afterID int64, limit int) (int64, int64, error) {
	f.calls = append(f.calls, batchCall{afterID, limit})
	if f.err != nil {
		return 0, 0, f.err
	}
	if len(f.calls) > len(f.batches) {
		return 0, 0, nil
	}
	b := f.batches[len(f.calls)-1]
	return b[0], b[1], nil
}

func runningContext() *mockjobservice.MockJobContext {
	ctx := &mockjobservice.MockJobContext{}
	ctx.On("OPCommand").Return(job.NilCommand, false)
	return ctx
}

func TestCleanupAdvancesTheCursorUntilTheTableEnds(t *testing.T) {
	// The second batch deletes nothing and must not end the run: records above it can be unlinked.
	dao := &fakeDao{batches: [][2]int64{{batchSize, 9000}, {0, 20000}, {7, 20500}}}
	require.NoError(t, (&Cleanup{dao: dao}).Run(runningContext(), nil))
	require.Equal(t, []batchCall{{0, batchSize}, {9000, batchSize}, {20000, batchSize}, {20500, batchSize}}, dao.calls)
}

func TestCleanupOnAnEmptyTableRunsOneBatch(t *testing.T) {
	dao := &fakeDao{}
	require.NoError(t, (&Cleanup{dao: dao}).Run(runningContext(), nil))
	require.Len(t, dao.calls, 1)
}

func TestCleanupReturnsTheBatchError(t *testing.T) {
	dao := &fakeDao{err: errors.New("connection reset")}
	require.Error(t, (&Cleanup{dao: dao}).Run(runningContext(), nil))
}

func TestCleanupStopsOnTheStopCommand(t *testing.T) {
	dao := &fakeDao{batches: [][2]int64{{batchSize, 9000}}}
	ctx := &mockjobservice.MockJobContext{}
	ctx.On("OPCommand").Return(job.StopCommand, true)
	require.NoError(t, (&Cleanup{dao: dao}).Run(ctx, nil))
	require.Empty(t, dao.calls)
}
