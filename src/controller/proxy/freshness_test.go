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
	"testing"
	"time"

	"github.com/docker/distribution"
	"github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/goharbor/harbor/src/controller/artifact"
	"github.com/goharbor/harbor/src/lib"
	"github.com/goharbor/harbor/src/lib/cache"
	_ "github.com/goharbor/harbor/src/lib/cache/memory"
	"github.com/goharbor/harbor/src/lib/errors"
	pkgart "github.com/goharbor/harbor/src/pkg/artifact"
	proModels "github.com/goharbor/harbor/src/pkg/project/models"
	testproxy "github.com/goharbor/harbor/src/testing/controller/proxy"
)

const (
	digestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digestB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

type freshnessRig struct {
	t      *testing.T
	ctl    *controller
	local  *localInterfaceMock
	remote *testproxy.RemoteInterface
	clock  time.Time
}

func newFreshnessRig(t *testing.T) *freshnessRig {
	c, err := cache.New(cache.Memory)
	require.NoError(t, err)
	r := &freshnessRig{
		t:      t,
		local:  &localInterfaceMock{},
		remote: &testproxy.RemoteInterface{},
		clock:  time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC),
	}
	r.ctl = &controller{local: r.local, cache: c}
	orig := now
	now = func() time.Time { return r.clock }
	t.Cleanup(func() { now = orig })
	return r
}

func (r *freshnessRig) localDigest(dig string) {
	r.local.ExpectedCalls = nil
	if dig == "" {
		r.local.On("GetManifest", mock.Anything, mock.Anything).Return(nil, nil)
		return
	}
	r.local.On("GetManifest", mock.Anything, mock.Anything).Return(&artifact.Artifact{Artifact: pkgart.Artifact{Digest: dig}}, nil)
}

func (r *freshnessRig) upstreamDigest(dig string) {
	r.remote.ExpectedCalls = nil
	r.remote.Calls = nil
	r.remote.On("ManifestExist", mock.Anything, mock.Anything).Return(true, &distribution.Descriptor{Digest: digest.Digest(dig)}, nil)
}

func (r *freshnessRig) upstreamMissing() {
	r.remote.ExpectedCalls = nil
	r.remote.Calls = nil
	r.remote.On("ManifestExist", mock.Anything, mock.Anything).Return(false, nil, nil)
}

func (r *freshnessRig) upstreamDown() {
	r.remote.ExpectedCalls = nil
	r.remote.Calls = nil
	r.remote.On("ManifestExist", mock.Anything, mock.Anything).Return(false, nil, errors.New("dial tcp: connection refused"))
}

func (r *freshnessRig) pull(p *proModels.Project, art lib.ArtifactInfo) (bool, error) {
	useLocal, _, err := r.ctl.UseLocalManifest(context.Background(), art, r.remote, p)
	return useLocal, err
}

func (r *freshnessRig) heads() int {
	n := 0
	for _, c := range r.remote.Calls {
		if c.Method == "ManifestExist" {
			n++
		}
	}
	return n
}

func proxyProject(meta map[string]string) *proModels.Project {
	return &proModels.Project{Name: "hub", RegistryID: 1, Metadata: meta}
}

var tagArt = lib.ArtifactInfo{ProjectName: "hub", Repository: "hub/library/nginx", Tag: "latest"}

func TestTagPullInsideRefreshWindowSkipsUpstream(t *testing.T) {
	r := newFreshnessRig(t)
	p := proxyProject(nil)
	r.localDigest(digestA)
	r.upstreamDigest(digestA)

	useLocal, err := r.pull(p, tagArt)
	require.NoError(t, err)
	require.True(t, useLocal)
	require.Equal(t, 1, r.heads())

	r.clock = r.clock.Add(1439 * time.Minute)
	useLocal, err = r.pull(p, tagArt)
	require.NoError(t, err)
	require.True(t, useLocal)
	require.Equal(t, 1, r.heads(), "second pull inside the default 1440 minute window must not ask upstream")
}

func TestTagPullAfterWindowSameDigestServesLocal(t *testing.T) {
	r := newFreshnessRig(t)
	p := proxyProject(map[string]string{proModels.ProMetaProxyCacheRefreshDuration: "60"})
	r.localDigest(digestA)
	r.upstreamDigest(digestA)
	_, err := r.pull(p, tagArt)
	require.NoError(t, err)

	r.clock = r.clock.Add(61 * time.Minute)
	useLocal, err := r.pull(p, tagArt)
	require.NoError(t, err)
	require.True(t, useLocal)
	require.Equal(t, 2, r.heads())

	// the HEAD restarted the window
	useLocal, err = r.pull(p, tagArt)
	require.NoError(t, err)
	require.True(t, useLocal)
	require.Equal(t, 2, r.heads())
}

func TestTagPullAfterWindowChangedDigestRepulls(t *testing.T) {
	r := newFreshnessRig(t)
	p := proxyProject(map[string]string{proModels.ProMetaProxyCacheRefreshDuration: "60"})
	r.localDigest(digestA)
	r.upstreamDigest(digestA)
	_, err := r.pull(p, tagArt)
	require.NoError(t, err)

	r.clock = r.clock.Add(2 * time.Hour)
	r.upstreamDigest(digestB)
	useLocal, err := r.pull(p, tagArt)
	require.NoError(t, err)
	require.False(t, useLocal, "a changed upstream digest must be pulled again")
	require.Equal(t, 1, r.heads())

	// the new digest is recorded: once the fill lands the next pull is local without a HEAD
	r.localDigest(digestB)
	useLocal, err = r.pull(p, tagArt)
	require.NoError(t, err)
	require.True(t, useLocal)
	require.Equal(t, 1, r.heads())
}

func TestTagPullInsideWindowWithoutLocalCopyFetchesUpstream(t *testing.T) {
	r := newFreshnessRig(t)
	p := proxyProject(nil)
	r.localDigest("")
	r.upstreamDigest(digestA)
	useLocal, err := r.pull(p, tagArt)
	require.NoError(t, err)
	require.False(t, useLocal)

	// nothing cached for the recorded digest (fill pending, GC, retention): ask upstream, never serve what is not stored
	useLocal, err = r.pull(p, tagArt)
	require.NoError(t, err)
	require.False(t, useLocal)
	require.Equal(t, 2, r.heads())
}

func TestTagPullUpstreamDownServesCachedCopy(t *testing.T) {
	r := newFreshnessRig(t)
	p := proxyProject(map[string]string{proModels.ProMetaProxyCacheRefreshDuration: "60"})
	r.localDigest(digestA)
	r.upstreamDigest(digestA)
	_, err := r.pull(p, tagArt)
	require.NoError(t, err)

	r.clock = r.clock.Add(2 * time.Hour)
	r.upstreamDown()
	useLocal, err := r.pull(p, tagArt)
	require.NoError(t, err)
	require.True(t, useLocal)
	require.Equal(t, 1, r.heads())
}

func TestTagPullUpstreamDownWithoutLocalCopyFails(t *testing.T) {
	r := newFreshnessRig(t)
	r.localDigest("")
	r.upstreamDown()
	_, err := r.pull(proxyProject(nil), tagArt)
	require.Error(t, err)
}

func TestDigestPullNeverRefreshes(t *testing.T) {
	r := newFreshnessRig(t)
	p := proxyProject(map[string]string{proModels.ProMetaProxyCacheRefreshDuration: "1"})
	r.localDigest(digestA)
	r.upstreamDigest(digestB)
	art := lib.ArtifactInfo{ProjectName: "hub", Repository: "hub/library/nginx", Digest: digestA}
	for range 3 {
		r.clock = r.clock.Add(time.Hour)
		useLocal, err := r.pull(p, art)
		require.NoError(t, err)
		require.True(t, useLocal)
	}
	require.Equal(t, 0, r.heads())
}

func TestCachedMissInsideWindow(t *testing.T) {
	r := newFreshnessRig(t)
	p := proxyProject(nil)
	r.localDigest("")
	r.upstreamMissing()

	_, err := r.pull(p, tagArt)
	require.True(t, errors.IsNotFoundErr(err))
	require.Equal(t, 1, r.heads())

	r.clock = r.clock.Add(9 * time.Minute)
	_, err = r.pull(p, tagArt)
	require.True(t, errors.IsNotFoundErr(err))
	require.Equal(t, 1, r.heads(), "a 404 inside the default 10 minute miss window must not ask upstream")
}

func TestCachedMissAfterWindowAsksAgain(t *testing.T) {
	r := newFreshnessRig(t)
	p := proxyProject(map[string]string{proModels.ProMetaProxyCacheMissDuration: "5"})
	r.localDigest("")
	r.upstreamMissing()
	_, err := r.pull(p, tagArt)
	require.True(t, errors.IsNotFoundErr(err))

	r.clock = r.clock.Add(5 * time.Minute)
	r.upstreamDigest(digestA)
	useLocal, err := r.pull(p, tagArt)
	require.NoError(t, err)
	require.False(t, useLocal)
	require.Equal(t, 1, r.heads())
}

func TestCachedMissDigestPull(t *testing.T) {
	r := newFreshnessRig(t)
	p := proxyProject(nil)
	r.localDigest("")
	r.upstreamMissing()
	art := lib.ArtifactInfo{ProjectName: "hub", Repository: "hub/library/nginx", Digest: digestA}
	for range 3 {
		_, err := r.pull(p, art)
		require.True(t, errors.IsNotFoundErr(err))
	}
	require.Equal(t, 1, r.heads())
}

func TestCachedMissKeepsLocalOnNotFound(t *testing.T) {
	r := newFreshnessRig(t)
	p := proxyProject(map[string]string{
		proModels.ProMetaProxyCacheLocalOnNotFound: "true",
		proModels.ProMetaProxyCacheRefreshDuration: "1",
	})
	r.localDigest(digestA)
	r.upstreamMissing()
	for range 3 {
		useLocal, err := r.pull(p, tagArt)
		require.NoError(t, err)
		require.True(t, useLocal)
	}
	require.Equal(t, 1, r.heads())
}

func TestNeverRecheck(t *testing.T) {
	r := newFreshnessRig(t)
	p := proxyProject(map[string]string{
		proModels.ProMetaProxyCacheRefreshDuration: "-1",
		proModels.ProMetaProxyCacheMissDuration:    "-1",
	})
	r.localDigest(digestA)
	r.upstreamDigest(digestA)
	_, err := r.pull(p, tagArt)
	require.NoError(t, err)

	missing := lib.ArtifactInfo{ProjectName: "hub", Repository: "hub/library/nginx", Tag: "gone"}
	r.localDigest("")
	r.remote.ExpectedCalls = nil
	r.remote.On("ManifestExist", mock.Anything, "gone").Return(false, nil, nil)
	_, err = r.pull(p, missing)
	require.True(t, errors.IsNotFoundErr(err))
	require.Equal(t, 2, r.heads())

	r.clock = r.clock.Add(365 * 24 * time.Hour)
	r.localDigest(digestA)
	useLocal, err := r.pull(p, tagArt)
	require.NoError(t, err)
	require.True(t, useLocal)
	r.localDigest("")
	_, err = r.pull(p, missing)
	require.True(t, errors.IsNotFoundErr(err))
	require.Equal(t, 2, r.heads())
}

func TestShorterWindowAppliesToExistingRecords(t *testing.T) {
	r := newFreshnessRig(t)
	p := proxyProject(nil)
	r.localDigest(digestA)
	r.upstreamDigest(digestA)
	_, err := r.pull(p, tagArt)
	require.NoError(t, err)

	r.clock = r.clock.Add(30 * time.Minute)
	p.Metadata = map[string]string{proModels.ProMetaProxyCacheRefreshDuration: "15"}
	_, err = r.pull(p, tagArt)
	require.NoError(t, err)
	require.Equal(t, 2, r.heads())
}

func TestInvalidStoredDurationFallsBackToDefault(t *testing.T) {
	p := proxyProject(map[string]string{
		proModels.ProMetaProxyCacheRefreshDuration: "0",
		proModels.ProMetaProxyCacheMissDuration:    "abc",
	})
	require.Equal(t, proModels.CacheWindow{Duration: 1440 * time.Minute}, p.ProxyCacheRefreshWindow())
	require.Equal(t, proModels.CacheWindow{Duration: 10 * time.Minute}, p.ProxyCacheMissWindow())
}

func TestIndexPullUpstreamDownServesCachedManifestList(t *testing.T) {
	r := newFreshnessRig(t)
	p := proxyProject(map[string]string{proModels.ProMetaProxyCacheRefreshDuration: "60"})
	// an index is served from the manifest list cache; the local artifact holds the trimmed digest
	r.localDigest(digestB)
	listArt := tagArt
	listArt.Digest = digestA
	require.NoError(t, r.ctl.cache.Save(context.Background(), manifestListKey(tagArt.Repository, listArt), []byte("{}")))
	require.NoError(t, r.ctl.cache.Save(context.Background(), manifestListContentTypeKey(tagArt.Repository, listArt), "application/vnd.oci.image.index.v1+json"))
	r.upstreamDigest(digestA)
	useLocal, man, err := r.ctl.UseLocalManifest(context.Background(), tagArt, r.remote, p)
	require.NoError(t, err)
	require.True(t, useLocal)
	require.NotNil(t, man)

	r.clock = r.clock.Add(2 * time.Hour)
	r.upstreamDown()
	useLocal, man, err = r.ctl.UseLocalManifest(context.Background(), tagArt, r.remote, p)
	require.NoError(t, err)
	require.True(t, useLocal)
	require.NotNil(t, man)
	require.Equal(t, digestA, man.Digest)
	require.Equal(t, 1, r.heads())
}

type ttlRecorder struct {
	cache.Cache
	ttl map[string][]time.Duration
}

func (c *ttlRecorder) Save(ctx context.Context, key string, value any, expiration ...time.Duration) error {
	c.ttl[key] = expiration
	return c.Cache.Save(ctx, key, value, expiration...)
}

func TestRecordExpiration(t *testing.T) {
	r := newFreshnessRig(t)
	rec := &ttlRecorder{Cache: r.ctl.cache, ttl: map[string][]time.Duration{}}
	r.ctl.cache = rec
	ctx := context.Background()

	p := proxyProject(map[string]string{proModels.ProMetaProxyCacheRefreshDuration: "1", proModels.ProMetaProxyCacheMissDuration: "5"})
	r.ctl.saveTagCheck(ctx, p, tagArt.Repository, "a", digestA)
	r.ctl.saveMiss(ctx, p, tagArt.Repository, "b")
	// the tag record outlives its window so an unreachable upstream can still be answered
	require.Equal(t, []time.Duration{time.Minute + manifestListCacheInterval}, rec.ttl[tagCheckKey(0, tagArt.Repository, "a")])
	require.Equal(t, []time.Duration{5 * time.Minute}, rec.ttl[upstreamMissKey(0, tagArt.Repository, "b")])

	never := proxyProject(map[string]string{proModels.ProMetaProxyCacheRefreshDuration: "-1", proModels.ProMetaProxyCacheMissDuration: "-1"})
	r.ctl.saveTagCheck(ctx, never, tagArt.Repository, "c", digestA)
	r.ctl.saveMiss(ctx, never, tagArt.Repository, "d")
	require.Empty(t, rec.ttl[tagCheckKey(0, tagArt.Repository, "c")])
	require.Equal(t, []time.Duration{manifestListCacheInterval}, rec.ttl[upstreamMissKey(0, tagArt.Repository, "d")])
}

func TestTagMovedBetweenHeadAndGetIsReconciled(t *testing.T) {
	r := newFreshnessRig(t)
	p := proxyProject(nil)
	r.localDigest("")
	r.upstreamDigest(digestA)
	_, err := r.pull(p, tagArt)
	require.NoError(t, err)

	// the GET fetched the tag after it moved, so B is cached while the record says A
	r.localDigest(digestB)
	r.upstreamDigest(digestB)
	useLocal, err := r.pull(p, tagArt)
	require.NoError(t, err)
	require.True(t, useLocal)
	require.Equal(t, 1, r.heads())

	useLocal, err = r.pull(p, tagArt)
	require.NoError(t, err)
	require.True(t, useLocal)
	require.Equal(t, 1, r.heads(), "the record follows the cached digest after one HEAD")
}

func TestOutcomesReplaceEachOther(t *testing.T) {
	r := newFreshnessRig(t)
	ctx := context.Background()
	p := proxyProject(map[string]string{proModels.ProMetaProxyCacheMissDuration: "5"})
	r.localDigest(digestA)
	r.upstreamDigest(digestA)
	_, err := r.pull(p, tagArt)
	require.NoError(t, err)

	r.clock = r.clock.Add(25 * time.Hour)
	r.upstreamMissing()
	_, err = r.pull(p, tagArt)
	require.True(t, errors.IsNotFoundErr(err))
	dig, _ := r.ctl.lastTagCheck(ctx, p, tagArt.Repository, tagArt.Tag)
	require.Empty(t, dig, "a 404 drops the checked digest")

	r.clock = r.clock.Add(6 * time.Minute)
	r.upstreamDigest(digestA)
	_, err = r.pull(p, tagArt)
	require.NoError(t, err)
	p.Metadata[proModels.ProMetaProxyCacheMissDuration] = "30"
	require.False(t, r.ctl.recentMiss(ctx, p, tagArt.Repository, tagArt.Tag), "a found tag drops the miss")
}

func TestRecordsAreScopedToTheProject(t *testing.T) {
	r := newFreshnessRig(t)
	old := proxyProject(nil)
	old.ProjectID = 1
	r.localDigest("")
	r.upstreamMissing()
	_, err := r.pull(old, tagArt)
	require.True(t, errors.IsNotFoundErr(err))

	recreated := proxyProject(nil)
	recreated.ProjectID = 2
	r.upstreamDigest(digestA)
	_, err = r.pull(recreated, tagArt)
	require.NoError(t, err)
	require.Equal(t, 1, r.heads())
}

func TestDigestPullOfCachedIndexSkipsUpstream(t *testing.T) {
	r := newFreshnessRig(t)
	r.localDigest("")
	r.upstreamMissing()
	art := lib.ArtifactInfo{ProjectName: "hub", Repository: "hub/library/nginx", Digest: digestA}
	require.NoError(t, r.ctl.cache.Save(context.Background(), manifestListKey(art.Repository, art), []byte("{}")))
	require.NoError(t, r.ctl.cache.Save(context.Background(), manifestListContentTypeKey(art.Repository, art), "application/vnd.oci.image.index.v1+json"))
	useLocal, man, err := r.ctl.UseLocalManifest(context.Background(), art, r.remote, proxyProject(nil))
	require.NoError(t, err)
	require.True(t, useLocal)
	require.NotNil(t, man)
	require.Equal(t, 0, r.heads())
}
