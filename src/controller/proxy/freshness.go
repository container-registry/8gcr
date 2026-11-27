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

package proxy

import (
	"context"
	"fmt"
	"time"

	"github.com/goharbor/harbor/src/lib/cache"
	"github.com/goharbor/harbor/src/lib/errors"
	"github.com/goharbor/harbor/src/lib/log"
	proModels "github.com/goharbor/harbor/src/pkg/project/models"
)

// now is replaced in tests
var now = time.Now

// tagCheck records the upstream digest of a tag and when it was asked for.
type tagCheck struct {
	Digest    string    `json:"digest"`
	CheckedAt time.Time `json:"checked_at"`
}

// upstreamMiss records when upstream answered 404 for a reference.
type upstreamMiss struct {
	CheckedAt time.Time `json:"checked_at"`
}

// keys carry the project ID so a recreated project with the same name starts clean
func tagCheckKey(projectID int64, repo, tag string) string {
	return fmt.Sprintf("proxycache:checked:%d:%s:%s", projectID, repo, tag)
}

func upstreamMissKey(projectID int64, repo, ref string) string {
	return fmt.Sprintf("proxycache:miss:%d:%s:%s", projectID, repo, ref)
}

// lastTagCheck returns the last recorded upstream digest of a tag and whether it is inside the refresh window.
func (c *controller) lastTagCheck(ctx context.Context, p *proModels.Project, repo, tag string) (string, bool) {
	if c.cache == nil || p == nil {
		return "", false
	}
	var rec tagCheck
	if !c.fetchRecord(ctx, tagCheckKey(p.ProjectID, repo, tag), &rec) || rec.Digest == "" {
		return "", false
	}
	return rec.Digest, p.ProxyCacheRefreshWindow().Fresh(rec.CheckedAt, now())
}

func (c *controller) saveTagCheck(ctx context.Context, p *proModels.Project, repo, tag, dig string) {
	if c.cache == nil || p == nil || dig == "" {
		return
	}
	// kept past the window so an unreachable upstream can still be answered with the last digest
	ttl := p.ProxyCacheRefreshWindow().TTL()
	if ttl > 0 {
		ttl += manifestListCacheInterval
	}
	c.saveRecord(ctx, tagCheckKey(p.ProjectID, repo, tag), tagCheck{Digest: dig, CheckedAt: now()}, ttl)
}

// recentMiss reports whether upstream answered 404 for ref inside the miss window.
func (c *controller) recentMiss(ctx context.Context, p *proModels.Project, repo, ref string) bool {
	if c.cache == nil || p == nil {
		return false
	}
	var rec upstreamMiss
	if !c.fetchRecord(ctx, upstreamMissKey(p.ProjectID, repo, ref), &rec) {
		return false
	}
	return p.ProxyCacheMissWindow().Fresh(rec.CheckedAt, now())
}

func (c *controller) saveMiss(ctx context.Context, p *proModels.Project, repo, ref string) {
	if c.cache == nil || p == nil {
		return
	}
	// the reference is client-chosen, so a -1 window still gets a bounded record
	ttl := p.ProxyCacheMissWindow().TTL()
	if ttl == 0 {
		ttl = manifestListCacheInterval
	}
	c.saveRecord(ctx, upstreamMissKey(p.ProjectID, repo, ref), upstreamMiss{CheckedAt: now()}, ttl)
}

func (c *controller) clearTagCheck(ctx context.Context, p *proModels.Project, repo, tag string) {
	if c.cache != nil && p != nil {
		c.deleteRecord(ctx, tagCheckKey(p.ProjectID, repo, tag))
	}
}

func (c *controller) clearMiss(ctx context.Context, p *proModels.Project, repo, ref string) {
	if c.cache != nil && p != nil {
		c.deleteRecord(ctx, upstreamMissKey(p.ProjectID, repo, ref))
	}
}

func (c *controller) deleteRecord(ctx context.Context, key string) {
	if err := c.cache.Delete(ctx, key); err != nil && !errors.Is(err, cache.ErrNotFound) {
		log.Warningf("failed to delete proxy cache record %s: %v", key, err)
	}
}

func (c *controller) fetchRecord(ctx context.Context, key string, v any) bool {
	err := c.cache.Fetch(ctx, key, v)
	if err == nil {
		return true
	}
	if !errors.Is(err, cache.ErrNotFound) {
		log.Warningf("failed to read proxy cache record %s, asking upstream: %v", key, err)
	}
	return false
}

func (c *controller) saveRecord(ctx context.Context, key string, v any, ttl time.Duration) {
	var exp []time.Duration
	if ttl > 0 { // no expiration argument keeps the record forever on every backend
		exp = append(exp, ttl)
	}
	if err := c.cache.Save(ctx, key, v, exp...); err != nil {
		log.Warningf("failed to save proxy cache record %s: %v", key, err)
	}
}
