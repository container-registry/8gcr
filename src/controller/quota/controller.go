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

package quota

import (
	"context"
	"fmt"
	"strconv"
	"time"

	// quota driver
	_ "github.com/goharbor/harbor/src/controller/quota/driver"
	"github.com/goharbor/harbor/src/lib/config"
	"github.com/goharbor/harbor/src/lib/errors"
	"github.com/goharbor/harbor/src/lib/log"
	"github.com/goharbor/harbor/src/lib/orm"
	"github.com/goharbor/harbor/src/lib/q"
	"github.com/goharbor/harbor/src/lib/retry"
	"github.com/goharbor/harbor/src/pkg/quota"
	"github.com/goharbor/harbor/src/pkg/quota/driver"
	"github.com/goharbor/harbor/src/pkg/quota/types"

	// init the db config
	_ "github.com/goharbor/harbor/src/pkg/config/db"
)

func init() {
	if provider := config.GetQuotaUpdateProvider(); provider != "" && provider != "db" {
		log.Warningf("QUOTA_UPDATE_PROVIDER=%s is ignored: quota usage is always updated in the database", provider)
	}
}

var (
	defaultRetryTimeout = time.Minute * 5
	// rollbackTimeout bounds the detached rollback so it cannot pin a pool
	// connection behind a quota_usage row lock indefinitely
	rollbackTimeout = 30 * time.Second
)

var (
	// Ctl is a global quota controller instance
	Ctl = NewController()
)

// Controller defines the operations related with quotas
type Controller interface {
	// Count returns the total count of quotas according to the query.
	Count(ctx context.Context, query *q.Query) (int64, error)

	// Create ensure quota for the reference object
	Create(ctx context.Context, reference, referenceID string, hardLimits types.ResourceList, used ...types.ResourceList) (int64, error)

	// Delete delete quota by id
	Delete(ctx context.Context, id int64) error

	// Get returns quota by id
	Get(ctx context.Context, id int64, options ...Option) (*quota.Quota, error)

	// GetByRef returns quota by reference object
	GetByRef(ctx context.Context, reference, referenceID string, options ...Option) (*quota.Quota, error)

	// IsEnabled returns true when quota enabled for reference object
	IsEnabled(ctx context.Context, reference, referenceID string) (bool, error)

	// List list quotas
	List(ctx context.Context, query *q.Query, options ...Option) ([]*quota.Quota, error)

	// Refresh refresh quota for the reference object
	Refresh(ctx context.Context, reference, referenceID string, options ...Option) error

	// Request request resources to run f
	// Before run the function, it reserves the resources,
	// then runs f and refresh quota when f success，
	// in the finally it releases the resources which reserved at the beginning.
	Request(ctx context.Context, reference, referenceID string, resources types.ResourceList, f func() error) error

	// Update update quota
	Update(ctx context.Context, q *quota.Quota) error
}

// NewController creates an instance of the default quota controller
func NewController() Controller {
	return &controller{
		quotaMgr: quota.Mgr,
	}
}

type controller struct {
	quotaMgr quota.Manager
}

func (c *controller) Count(ctx context.Context, query *q.Query) (int64, error) {
	return c.quotaMgr.Count(ctx, query)
}

func (c *controller) Create(ctx context.Context, reference, referenceID string, hardLimits types.ResourceList, used ...types.ResourceList) (int64, error) {
	return c.quotaMgr.Create(ctx, reference, referenceID, hardLimits, used...)
}

func (c *controller) Delete(ctx context.Context, id int64) error {
	return c.quotaMgr.Delete(ctx, id)
}

func (c *controller) Get(ctx context.Context, id int64, options ...Option) (*quota.Quota, error) {
	q, err := c.quotaMgr.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	return c.assembleQuota(ctx, q, newOptions(options...))
}

func (c *controller) GetByRef(ctx context.Context, reference, referenceID string, options ...Option) (*quota.Quota, error) {
	q, err := c.quotaMgr.GetByRef(ctx, reference, referenceID)
	if err != nil {
		return nil, err
	}

	return c.assembleQuota(ctx, q, newOptions(options...))
}

func (c *controller) assembleQuota(ctx context.Context, q *quota.Quota, opts *Options) (*quota.Quota, error) {
	if opts.WithReferenceObject {
		driver, err := Driver(ctx, q.Reference)
		if err != nil {
			return nil, err
		}

		ref, err := driver.Load(ctx, q.ReferenceID)
		if err != nil {
			log.G(ctx).Warningf("failed to load referenced %s object %s for quota %d, error %v",
				q.Reference, q.ReferenceID, q.ID, err)
		} else {
			q.Ref = ref
		}
	}

	return q, nil
}

func (c *controller) IsEnabled(ctx context.Context, reference, referenceID string) (bool, error) {
	d, err := Driver(ctx, reference)
	if err != nil {
		return false, err
	}

	return d.Enabled(ctx, referenceID)
}

func (c *controller) List(ctx context.Context, query *q.Query, options ...Option) ([]*quota.Quota, error) {
	quotas, err := c.quotaMgr.List(ctx, query)
	if err != nil {
		return nil, err
	}

	opts := newOptions(options...)
	for _, q := range quotas {
		if _, err := c.assembleQuota(ctx, q, opts); err != nil {
			return nil, err
		}
	}

	return quotas, nil
}

// updateUsageByDB sets the usage to what op computes, as a compare-and-swap on
// the usage version. Refresh uses it to write an absolute figure.
func (c *controller) updateUsageByDB(ctx context.Context, reference, referenceID string, op func(hardLimits, used types.ResourceList) (types.ResourceList, error)) error {
	q, err := c.quotaMgr.GetByRef(ctx, reference, referenceID)
	if err != nil {
		return retry.Abort(err)
	}

	hardLimits, err := q.GetHard()
	if err != nil {
		return retry.Abort(err)
	}

	used, err := q.GetUsed()
	if err != nil {
		return retry.Abort(err)
	}

	newUsed, err := op(hardLimits, used)
	if err != nil {
		return retry.Abort(err)
	}

	// The PR https://github.com/goharbor/harbor/pull/17392 optimized the logic for post upload blob which use size 0
	// for checking quota, this will increase the pressure of optimistic lock, so here return earlier
	// if the quota usage has not changed to reduce the probability of optimistic lock.
	if types.Equals(used, newUsed) {
		return nil
	}

	q.SetUsed(newUsed)

	err = c.quotaMgr.Update(ctx, q)
	if err != nil && !errors.Is(err, orm.ErrOptimisticLock) {
		return retry.Abort(err)
	}

	return err
}

func (c *controller) updateUsageWithRetry(ctx context.Context, reference, referenceID string, op func(hardLimits, used types.ResourceList) (types.ResourceList, error), retryOpts ...retry.Option) error {
	f := func() error {
		return c.updateUsageByDB(ctx, reference, referenceID, op)
	}

	return retry.Retry(f, c.retryOptions(ctx, reference, referenceID, retryOpts...)...)
}

func (c *controller) retryOptions(ctx context.Context, reference, referenceID string, retryOpts ...retry.Option) []retry.Option {
	options := []retry.Option{
		retry.Timeout(defaultRetryTimeout),
		// Exponential backoff with jitter (the retry package default). With
		// backoff disabled, every optimistic-lock loser re-reads and re-CASes
		// the same quota_usage row in a zero-delay loop for up to
		// defaultRetryTimeout, so N concurrent pushes to one project turn a
		// single conflict into a synchronized retry storm on the database.
		retry.Backoff(true),
		// Give up as soon as the request is gone. An aborted push already
		// terminated on its next attempt (updateUsageByDB returns the
		// context error wrapped in retry.Abort); the context additionally
		// cancels an in-progress backoff sleep instead of letting it run
		// out and paying one more wasted attempt.
		retry.Context(ctx),
		retry.Callback(func(err error, _ time.Duration) {
			log.G(ctx).Debugf("failed to update the quota usage for %s %s, error: %v", reference, referenceID, err)
		}),
	}
	// append for override default retry options
	if len(retryOpts) > 0 {
		options = append(options, retryOpts...)
	}

	return options
}

// rollbackUsage returns resources reserved for an operation that then failed.
// It runs detached from its request, so the deadline on ctx is the only thing
// bounding it, and a Go deadline alone does not bound it: Beego's ORM takes no
// context, so an UPDATE already waiting on the quota_usage row lock keeps its
// pool connection until the lock holder commits. statementTimeout makes the
// database enforce the same deadline. The UPDATE is a single statement with no
// conflict to retry, and retrying after an unknown outcome could subtract the
// reservation twice, so it runs once.
func (c *controller) rollbackUsage(ctx context.Context, reference, referenceID string, resources types.ResourceList) error {
	return statementTimeout(func(ctx context.Context) error {
		applied, err := c.quotaMgr.AddUsage(ctx, reference, referenceID, negate(resources), false)
		if err == nil && !applied {
			// a refresh already recomputed the usage without this reservation
			return errors.New("usage is below the reservation, left unchanged")
		}
		return err
	})(orm.WithBoundedBegin(ctx))
}

// statementTimeout runs f in a transaction the database gives up on when ctx's
// deadline passes. transaction_timeout (Postgres 17+) bounds the rest of the
// transaction from the moment it is set; statement_timeout is the per-statement
// fallback on older servers. Both are transaction-local, so this leaves no
// setting behind on the pooled connection.
func statementTimeout(f func(ctx context.Context) error) func(ctx context.Context) error {
	return orm.WithTransaction(func(ctx context.Context) error {
		ormer, err := orm.FromContext(ctx)
		if err != nil {
			return err
		}

		// measured after Begin, which can wait on the pool, so a slow checkout
		// cannot hold a connection past the rollback bound
		timeout := rollbackTimeout
		if deadline, ok := ctx.Deadline(); ok {
			timeout = time.Until(deadline)
		}
		if timeout <= 0 {
			return context.DeadlineExceeded
		}
		// statement_timeout 0 means no timeout, so never round down to it
		timeout = max(timeout, time.Millisecond)

		// pg_settings filters out transaction_timeout where the server lacks it
		if _, err := ormer.Raw(`SELECT set_config(name, ?, true) FROM pg_settings
			WHERE name IN ('statement_timeout', 'transaction_timeout')`,
			strconv.FormatInt(timeout.Milliseconds(), 10)).Exec(); err != nil {
			return err
		}

		return f(ctx)
	})
}

func (c *controller) Refresh(ctx context.Context, reference, referenceID string, options ...Option) error {
	driver, err := Driver(ctx, reference)
	if err != nil {
		return err
	}

	opts := newOptions(options...)

	calculateUsage := func() (types.ResourceList, error) {
		newUsed, err := driver.CalculateUsage(ctx, referenceID)
		if err != nil {
			log.G(ctx).Errorf("failed to calculate quota usage for %s %s, error: %v", reference, referenceID, err)
			return nil, err
		}

		return newUsed, err
	}

	// update quota usage by db for refresh operation
	return c.updateUsageWithRetry(ctx, reference, referenceID, refreshResources(calculateUsage, opts.IgnoreLimitation), opts.RetryOptions...)
}

func (c *controller) Request(ctx context.Context, reference, referenceID string, resources types.ResourceList, f func() error) error {
	if len(resources) == 0 {
		return f()
	}

	// When every requested resource is unlimited, the reservation cannot
	// deny anything, so it would only add a write on the single quota_usage
	// row per project. Skip it and let the refresh (RefreshMiddleware /
	// Refresh) keep the usage figure up to date. Setting a real limit
	// refreshes the usage first (see Update), so enforcement starts from the
	// true figure.
	unlimited, q, err := c.isUnlimited(ctx, reference, referenceID, resources)
	if err == nil && unlimited {
		err := f()
		if err == nil {
			// the skipped reservation was also the only usage writer on
			// this path - keep the usage figure current via the deferred
			// coalesced refresh
			MarkRefresh(reference, referenceID)
		}
		return err
	} else if err != nil {
		log.G(ctx).Warningf("failed to check hard limits for %s %s, falling back to reservation, error: %v", reference, referenceID, err)
	}

	if allZero(resources) {
		// nothing to write (#17392 checks blob uploads with size 0); only
		// refuse when the usage is already over the limit
		if err := c.checkLimit(ctx, q, reference, referenceID, resources); err != nil {
			return err
		}
		return f()
	}

	// In the request transaction (PUT manifest), the row lock an UPDATE takes
	// is held until commit. Reserving before f would hold it across the
	// registry round-trip and serialize every push to the project, so the
	// UPDATE runs after f instead. A second connection would avoid that too,
	// but taking one while the transaction holds the first can deadlock the
	// pool (#850).
	if orm.InTransaction(ctx) {
		return c.requestLate(ctx, q, reference, referenceID, resources, f)
	}

	// Outside a transaction (blob uploads) the UPDATE commits on its own, so
	// the lock lasts one statement and the reservation can come first.
	applied, err := c.quotaMgr.AddUsage(ctx, reference, referenceID, resources, true)
	if err != nil {
		log.G(ctx).Errorf("reserve resources %s for %s %s failed, error: %v", resources.String(), reference, referenceID, err)
		return err
	}
	if !applied {
		return c.deniedError(ctx, reference, referenceID, resources)
	}

	err = f()

	if err != nil {
		// detached from the request: a client disconnect is the common failure
		// here, and the reservation may already be committed outside any request
		// transaction, so a canceled ctx would leave the usage inflated
		rbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
		defer cancel()
		if er := c.rollbackUsage(rbCtx, reference, referenceID, resources); er != nil {
			// ignore this error, the quota usage will be correct when users do operations which will call refresh quota
			log.G(ctx).Warningf("rollback resources %s for %s %s failed, error: %v", resources.String(), reference, referenceID, er)
		}
	}

	return err
}

// requestLate checks the limit read-only, runs f, and only then applies the
// conditional UPDATE in the request transaction, so the row lock lasts from
// the UPDATE to the commit instead of across f. A deny fails the request,
// which rolls the transaction back; nothing is reserved when f fails, so there
// is nothing to roll back. The read-only check keeps f from running when the
// usage is already known to be over the limit.
func (c *controller) requestLate(ctx context.Context, q *quota.Quota, reference, referenceID string, resources types.ResourceList, f func() error) error {
	if err := c.checkLimit(ctx, q, reference, referenceID, resources); err != nil {
		return err
	}
	if err := f(); err != nil {
		return err
	}
	applied, err := c.quotaMgr.AddUsage(ctx, reference, referenceID, resources, true)
	if err != nil {
		return err
	}
	if !applied {
		return c.deniedError(ctx, reference, referenceID, resources)
	}
	return nil
}

// checkLimit is overLimitError against q when the caller already read it.
func (c *controller) checkLimit(ctx context.Context, q *quota.Quota, reference, referenceID string, resources types.ResourceList) error {
	if q == nil {
		return c.overLimitError(ctx, reference, referenceID, resources)
	}
	return limitError(q, resources)
}

// deniedError is the error for a reservation the UPDATE refused. The usage
// can drop between the UPDATE and the read here; the request is denied anyway
// rather than retried, and still reports the overflow so the quota-exceeded
// event fires.
func (c *controller) deniedError(ctx context.Context, reference, referenceID string, resources types.ResourceList) error {
	q, err := c.quotaMgr.GetByRef(ctx, reference, referenceID)
	if err != nil {
		return err
	}
	if err := limitError(q, resources); err != nil {
		return err
	}
	hard, err := q.GetHard()
	if err != nil {
		return err
	}
	used, err := q.GetUsed()
	if err != nil {
		return err
	}
	var errs quota.Errors
	for name, v := range resources {
		errs = errs.Add(quota.NewResourceOverflowError(name, hard[name], used[name], used[name]+v))
	}
	return errors.DeniedError(errs).WithMessagef("Quota exceeded when processing the request of %v", errs)
}

// overLimitError returns the error a reservation of resources reports when it
// breaks a hard limit, the lookup error, or nil when it fits.
func (c *controller) overLimitError(ctx context.Context, reference, referenceID string, resources types.ResourceList) error {
	q, err := c.quotaMgr.GetByRef(ctx, reference, referenceID)
	if err != nil {
		return err
	}
	return limitError(q, resources)
}

func limitError(q *quota.Quota, resources types.ResourceList) error {
	hard, err := q.GetHard()
	if err != nil {
		return err
	}
	used, err := q.GetUsed()
	if err != nil {
		return err
	}
	if err := quota.IsSafe(hard, used, types.Add(used, resources), false); err != nil {
		return errors.DeniedError(err).WithMessagef("Quota exceeded when processing the request of %v", err)
	}
	return nil
}

// isUnlimited reports whether every resource in the request has an
// UNLIMITED hard limit for the reference, in which case a reservation can
// never deny the request. It returns the quota it read for reuse.
func (c *controller) isUnlimited(ctx context.Context, reference, referenceID string, resources types.ResourceList) (bool, *quota.Quota, error) {
	q, err := c.quotaMgr.GetByRef(ctx, reference, referenceID)
	if err != nil {
		return false, nil, err
	}

	hardLimits, err := q.GetHard()
	if err != nil {
		return false, nil, err
	}

	for resource := range resources {
		hardLimit, found := hardLimits[resource]
		if !found || hardLimit != types.UNLIMITED {
			return false, q, nil
		}
	}

	return true, q, nil
}

func (c *controller) Update(ctx context.Context, u *quota.Quota) error {
	hardChanged := false
	f := func() error {
		q, err := c.quotaMgr.GetByRef(ctx, u.Reference, u.ReferenceID)
		if err != nil {
			return err
		}

		if oldHard, err := q.GetHard(); err == nil {
			if newHard, err := u.GetHard(); err == nil {
				if !types.Equals(oldHard, newHard) {
					q.SetHard(newHard)
					hardChanged = true
				}
			}
		}

		if oldUsed, err := q.GetUsed(); err == nil {
			if newUsed, err := u.GetUsed(); err == nil {
				if !types.Equals(oldUsed, newUsed) {
					q.SetUsed(newUsed)
				}
			}
		}

		return c.quotaMgr.Update(ctx, q)
	}

	options := []retry.Option{
		retry.Timeout(defaultRetryTimeout),
		// See updateUsageWithRetry: backoff+jitter desynchronizes writers
		// contending on the single quota row.
		retry.Backoff(true),
		retry.Context(ctx),
	}

	if err := retry.Retry(f, options...); err != nil {
		return err
	}

	if hardChanged {
		// Unlimited requests skip the reservation and leave the usage to the
		// in-memory deferred refresh, which a restart can lose. Recompute it
		// now so the new limit is enforced against the real usage. Requests
		// admitted between the limit commit and this refresh still see the
		// old usage; that window is one refresh long.
		if err := c.Refresh(ctx, u.Reference, u.ReferenceID, IgnoreLimitation(true)); err != nil {
			log.G(ctx).Warningf("failed to refresh usage of %s %s after hard limit change, deferring, error: %v", u.Reference, u.ReferenceID, err)
			MarkRefresh(u.Reference, u.ReferenceID)
		}
	}

	return nil
}

// Driver returns quota driver for the reference
func Driver(_ context.Context, reference string) (driver.Driver, error) {
	d, ok := driver.Get(reference)
	if !ok {
		return nil, fmt.Errorf("quota not support for %s", reference)
	}

	return d, nil
}

// Validate validate hard limits
func Validate(ctx context.Context, reference string, hardLimits types.ResourceList) error {
	d, err := Driver(ctx, reference)
	if err != nil {
		return err
	}

	return d.Validate(hardLimits)
}

func refreshResources(calculateUsage func() (types.ResourceList, error), ignoreLimitation bool) func(hardLimits, used types.ResourceList) (types.ResourceList, error) {
	return func(hardLimits, used types.ResourceList) (types.ResourceList, error) {
		newUsed, err := calculateUsage()
		if err != nil {
			return nil, err
		}

		// ensure that new used is never negative
		if negativeUsed := types.IsNegative(newUsed); len(negativeUsed) > 0 {
			return nil, fmt.Errorf("quota usage is negative for resource(s): %s", quota.PrettyPrintResourceNames(negativeUsed))
		}

		if err := quota.IsSafe(hardLimits, used, newUsed, ignoreLimitation); err != nil {
			return nil, err
		}

		return newUsed, nil
	}
}

func allZero(r types.ResourceList) bool {
	for _, v := range r {
		if v != 0 {
			return false
		}
	}
	return true
}

func negate(r types.ResourceList) types.ResourceList {
	n := make(types.ResourceList, len(r))
	for k, v := range r {
		n[k] = -v
	}
	return n
}
