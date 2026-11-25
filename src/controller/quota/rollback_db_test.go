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

//go:build db

package quota

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/suite"

	"github.com/goharbor/harbor/src/lib/orm"
	"github.com/goharbor/harbor/src/pkg/quota"
	"github.com/goharbor/harbor/src/pkg/quota/types"
	htesting "github.com/goharbor/harbor/src/testing"
	"github.com/goharbor/harbor/src/testing/mock"
	quotatesting "github.com/goharbor/harbor/src/testing/pkg/quota"
)

type RollbackTestSuite struct {
	htesting.Suite

	ctl       *controller
	reference string
}

func (suite *RollbackTestSuite) SetupSuite() {
	suite.Suite.SetupSuite()
	suite.Suite.ClearSQLs = []string{
		"DELETE FROM quota WHERE id > 1",
		"DELETE FROM quota_usage WHERE id > 1",
	}
	suite.ctl = &controller{quotaMgr: quota.Mgr}
	suite.reference = "rollback-bound"
}

// lockUsageRow holds the quota_usage row's write lock, on a connection of its
// own, until the returned function is called or lockHoldLimit passes. The
// rollback CAS updates that row, so it waits for the lock; the time limit
// turns a rollback that ignores its deadline into a failure, not a hang.
func (suite *RollbackTestSuite) lockUsageRow(id int64) func() {
	locked := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})

	go func() {
		defer close(done)
		err := orm.WithTransaction(func(ctx context.Context) error {
			o, err := orm.FromContext(ctx)
			if err != nil {
				return err
			}
			var ids []int64
			if _, err := o.Raw("SELECT id FROM quota_usage WHERE id = ? FOR UPDATE", id).QueryRows(&ids); err != nil {
				return err
			}
			close(locked)
			select {
			case <-release:
			case <-time.After(lockHoldLimit):
			}
			return nil
		})(orm.Context())
		suite.NoError(err)
	}()

	select {
	case <-locked:
	case <-done:
		suite.FailNow("the lock holder exited before taking the row lock")
	}
	var once sync.Once
	return func() {
		once.Do(func() { close(release) })
		<-done
	}
}

// lockHoldLimit bounds how long lockUsageRow holds its lock.
const lockHoldLimit = 5 * time.Second

// TestRollbackGivesUpOnALockedRow is the regression test for the deadline that
// was not one. The rollback UPDATE runs through Beego's ORM, which takes no
// context, so before the database was told the deadline too, the UPDATE sat
// on the row lock with a pool connection in hand for as long as the lock
// holder wanted - the whole failure this timeout exists to prevent.
func (suite *RollbackTestSuite) TestRollbackGivesUpOnALockedRow() {
	ctx := orm.Context()
	hard := types.ResourceList{types.ResourceStorage: 100}
	id, err := quota.Mgr.Create(ctx, suite.reference, uuid.New().String(), hard, types.ResourceList{types.ResourceStorage: 10})
	suite.Require().NoError(err)
	q, err := quota.Mgr.Get(ctx, id)
	suite.Require().NoError(err)

	defer suite.lockUsageRow(id)()

	// short enough that a test waiting out the lock is unmistakable, and the
	// same value reaches both the context and statement_timeout, exactly as
	// the rollback path in Request sets it up
	original := rollbackTimeout
	rollbackTimeout = time.Second
	defer func() { rollbackTimeout = original }()

	rbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
	defer cancel()

	start := time.Now()
	err = suite.ctl.rollbackUsage(rbCtx, q.Reference, q.ReferenceID, types.ResourceList{types.ResourceStorage: 10})
	elapsed := time.Since(start)

	suite.Error(err, "the rollback cannot succeed while another transaction holds the row")
	// scheduling slack only; a rollback that ignores its deadline waits out lockHoldLimit
	suite.Less(elapsed, rollbackTimeout+500*time.Millisecond, "the rollback overran its own deadline")
}

// TestRollbackDoesNotRetry: an error leaves the outcome unknown, so the
// rollback must end after one attempt instead of subtracting the reservation
// again.
func (suite *RollbackTestSuite) TestRollbackDoesNotRetry() {
	mgr := &quotatesting.Manager{}
	mock.OnAnything(mgr, "AddUsage").Return(false, errors.New("commit outcome unknown"))
	ctl := &controller{quotaMgr: mgr}

	rbCtx, cancel := context.WithTimeout(orm.Context(), rollbackTimeout)
	defer cancel()

	err := ctl.rollbackUsage(rbCtx, suite.reference, uuid.New().String(), types.ResourceList{types.ResourceStorage: 10})
	suite.Error(err)
	mgr.AssertNumberOfCalls(suite.T(), "AddUsage", 1)
}

// TestRollbackAbortsOnExpiredDeadline: with no time left there is nothing to
// give the database as statement_timeout, so no attempt may start.
func (suite *RollbackTestSuite) TestRollbackAbortsOnExpiredDeadline() {
	mgr := &quotatesting.Manager{}
	ctl := &controller{quotaMgr: mgr}

	rbCtx, cancel := context.WithDeadline(orm.Context(), time.Now().Add(-time.Second))
	defer cancel()

	err := ctl.rollbackUsage(rbCtx, suite.reference, uuid.New().String(), types.ResourceList{types.ResourceStorage: 10})
	suite.Error(err)
	mgr.AssertNotCalled(suite.T(), "AddUsage", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// TestRequestFailureInsideTransaction: inside a transaction the reservation
// runs after f, so a failed f reserves nothing, and the usage ends where it
// started whether the transaction then commits or rolls back.
func (suite *RollbackTestSuite) TestRequestFailureInsideTransaction() {
	for _, commit := range []bool{true, false} {
		ctx := orm.Context()
		id, err := quota.Mgr.Create(ctx, suite.reference, uuid.New().String(), types.ResourceList{types.ResourceStorage: 100}, types.ResourceList{types.ResourceStorage: 10})
		suite.Require().NoError(err)
		q, err := quota.Mgr.Get(ctx, id)
		suite.Require().NoError(err)

		failed := errors.New("upload failed")
		txErr := orm.WithTransaction(func(ctx context.Context) error {
			err := suite.ctl.Request(ctx, q.Reference, q.ReferenceID, types.ResourceList{types.ResourceStorage: 50}, func() error { return failed })
			suite.ErrorIs(err, failed)
			if commit {
				return nil
			}
			return err
		})(ctx)
		suite.Equal(!commit, txErr != nil)

		q, err = quota.Mgr.Get(ctx, id)
		suite.Require().NoError(err)
		used, err := q.GetUsed()
		suite.Require().NoError(err)
		suite.Equal(int64(10), used[types.ResourceStorage], "commit=%v", commit)
	}
}

// TestRollbackAfterRefreshKeepsUsage: a refresh between the reservation and
// the failed upload already recomputed the usage without the reservation, so
// the rollback must not subtract it again and erase other usage.
func (suite *RollbackTestSuite) TestRollbackAfterRefreshKeepsUsage() {
	ctx := orm.Context()
	id, err := quota.Mgr.Create(ctx, suite.reference, uuid.New().String(), types.ResourceList{types.ResourceStorage: 1000}, types.ResourceList{types.ResourceStorage: 50})
	suite.Require().NoError(err)
	q, err := quota.Mgr.Get(ctx, id)
	suite.Require().NoError(err)

	failed := errors.New("upload failed")
	err = suite.ctl.Request(ctx, q.Reference, q.ReferenceID, types.ResourceList{types.ResourceStorage: 100}, func() error {
		refreshed, err := quota.Mgr.Get(ctx, id)
		suite.Require().NoError(err)
		refreshed.SetUsed(types.ResourceList{types.ResourceStorage: 50})
		suite.Require().NoError(quota.Mgr.Update(ctx, refreshed))
		return failed
	})
	suite.ErrorIs(err, failed)

	q, err = quota.Mgr.Get(ctx, id)
	suite.Require().NoError(err)
	used, err := q.GetUsed()
	suite.Require().NoError(err)
	suite.Equal(int64(50), used[types.ResourceStorage])
}

// TestRequestInTransactionEnforcesUnderConcurrency: with the reservation after
// f, concurrent requests in their own transactions still never exceed the
// limit, and a denied request rolls back without leaving usage behind.
func (suite *RollbackTestSuite) TestRequestInTransactionEnforcesUnderConcurrency() {
	ctx := orm.Context()
	id, err := quota.Mgr.Create(ctx, suite.reference, uuid.New().String(), types.ResourceList{types.ResourceStorage: 100}, types.ResourceList{types.ResourceStorage: 0})
	suite.Require().NoError(err)
	q, err := quota.Mgr.Get(ctx, id)
	suite.Require().NoError(err)

	var ok atomic.Int64
	var wg sync.WaitGroup
	for range 25 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := orm.WithTransaction(func(ctx context.Context) error {
				return suite.ctl.Request(ctx, q.Reference, q.ReferenceID, types.ResourceList{types.ResourceStorage: 10}, func() error {
					time.Sleep(20 * time.Millisecond)
					return nil
				})
			})(orm.Context())
			if err == nil {
				ok.Add(1)
			}
		}()
	}
	wg.Wait()

	suite.Equal(int64(10), ok.Load())
	q, err = quota.Mgr.Get(ctx, id)
	suite.Require().NoError(err)
	used, err := q.GetUsed()
	suite.Require().NoError(err)
	suite.Equal(int64(100), used[types.ResourceStorage])
}

func TestRollbackTestSuite(t *testing.T) {
	suite.Run(t, &RollbackTestSuite{})
}
