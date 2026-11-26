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
	"io"
	"strings"
	"sync"
	"time"

	"github.com/docker/distribution"
	"github.com/opencontainers/go-digest"

	"github.com/goharbor/harbor/src/controller/artifact"
	"github.com/goharbor/harbor/src/controller/blob"
	"github.com/goharbor/harbor/src/controller/event/metadata/requestinfo"
	"github.com/goharbor/harbor/src/controller/event/operator"
	"github.com/goharbor/harbor/src/controller/tag"
	"github.com/goharbor/harbor/src/lib"
	"github.com/goharbor/harbor/src/lib/cache"
	"github.com/goharbor/harbor/src/lib/errors"
	"github.com/goharbor/harbor/src/lib/log"
	"github.com/goharbor/harbor/src/lib/orm"
	proModels "github.com/goharbor/harbor/src/pkg/project/models"
	model_tag "github.com/goharbor/harbor/src/pkg/tag/model/tag"
)

const (
	// keep manifest list in cache for one week
	manifestListCacheInterval = 7 * 24 * 60 * 60 * time.Second
)

var (
	// wait more time than manifest (maxManifestWait) because manifest list depends on manifest ready
	maxManifestListWait = 20
	maxManifestWait     = 10
	sleepIntervalSec    = 20
	// Ctl is a global proxy controller instance
	ctl  Controller
	once sync.Once
)

// Controller defines the operations related with pull through proxy
type Controller interface {
	// UseLocalBlob check if the blob should use local copy
	UseLocalBlob(ctx context.Context, art lib.ArtifactInfo) bool
	// UseLocalManifest check manifest should use local copy
	UseLocalManifest(ctx context.Context, art lib.ArtifactInfo, remote RemoteInterface, p *proModels.Project) (bool, *ManifestList, error)
	// ProxyBlob proxy the blob request to the remote server, p is the proxy project
	// art is the ArtifactInfo which includes the digest of the blob
	ProxyBlob(ctx context.Context, p *proModels.Project, art lib.ArtifactInfo) (int64, io.ReadCloser, error)
	// ProxyManifest proxy the manifest request to the remote server, p is the proxy project,
	// art is the ArtifactInfo which includes the tag or digest of the manifest
	ProxyManifest(ctx context.Context, art lib.ArtifactInfo, remote RemoteInterface) (distribution.Manifest, error)
	// HeadManifest send manifest head request to the remote server
	HeadManifest(ctx context.Context, art lib.ArtifactInfo, remote RemoteInterface) (bool, *distribution.Descriptor, error)
	// EnsureTag ensure tag for digest
	EnsureTag(ctx context.Context, art lib.ArtifactInfo, tagName string) error
}

type controller struct {
	blobCtl         blob.Controller
	artifactCtl     artifact.Controller
	local           localInterface
	cache           cache.Cache
	handlerRegistry map[string]ManifestCacheHandler
}

// ControllerInstance -- Get the proxy controller instance
func ControllerInstance() Controller {
	// Lazy load the controller
	// Because LocalHelper is not ready unless core startup completely
	once.Do(func() {
		l := newLocalHelper()
		ctl = &controller{
			blobCtl:         blob.Ctl,
			artifactCtl:     artifact.Ctl,
			local:           newLocalHelper(),
			cache:           cache.Default(),
			handlerRegistry: NewCacheHandlerRegistry(l),
		}
	})

	return ctl
}

func (c *controller) EnsureTag(ctx context.Context, art lib.ArtifactInfo, tagName string) error {
	// search the digest in cache and query with trimmed digest
	var trimmedDigest string
	err := c.cache.Fetch(ctx, TrimmedManifestlist+art.Digest, &trimmedDigest)
	if errors.Is(err, cache.ErrNotFound) { //nolint:revive
		// skip to update digest, continue
	} else if err != nil {
		// for other error, return
		return err
	} else {
		// found in redis, update the digest
		art.Digest = trimmedDigest
		log.Debugf("Found trimmed digest: %v", trimmedDigest)
	}
	a, err := c.local.GetManifest(ctx, art)
	if err != nil {
		return err
	}
	if a == nil {
		return fmt.Errorf("the artifact is not ready yet, failed to tag it to %v", tagName)
	}
	tagID, err := tag.Ctl.Ensure(ctx, a.RepositoryID, a.Artifact.ID, tagName)
	if err != nil {
		return err
	}
	// update the pull time of tag for the first time cache
	return tag.Ctl.Update(ctx, &tag.Tag{
		Tag: model_tag.Tag{
			ID:       tagID,
			PullTime: time.Now(),
		},
	}, "PullTime")
}

func (c *controller) UseLocalBlob(ctx context.Context, art lib.ArtifactInfo) bool {
	if len(art.Digest) == 0 {
		return false
	}
	exist, err := c.local.BlobExist(ctx, art)
	if err != nil {
		return false
	}
	return exist
}

// ManifestList ...
type ManifestList struct {
	Content     []byte
	Digest      string
	ContentType string
}

// UseLocalManifest check if these manifest could be found in local registry,
// the return error should be nil when it is not found in local and need to delegate to remote registry
// the return error should be NotFoundError when it is not found in remote registry
// the error will be captured by framework and return 404 to client
func (c *controller) UseLocalManifest(ctx context.Context, art lib.ArtifactInfo, remote RemoteInterface, p *proModels.Project) (bool, *ManifestList, error) {
	a, err := c.local.GetManifest(ctx, art)
	if err != nil {
		return false, nil, err
	}
	// Pull by digest when artifact exist in local
	if a != nil && len(art.Digest) > 0 {
		return true, nil, nil
	}
	// digest pulls never refresh, so a cached original index needs no upstream call
	if len(art.Digest) > 0 {
		if ok, man := c.servable(ctx, nil, art, art.Digest); ok {
			return true, man, nil
		}
	}

	ref := getReference(art)
	if c.recentMiss(ctx, p, art.Repository, ref) {
		log.Debugf("upstream answered 404 for %v:%v inside the miss window, not asking again", art.Repository, ref)
		return c.upstreamNotFound(a, p, art)
	}

	var lastDigest string
	if len(art.Digest) == 0 {
		dig, fresh := c.lastTagCheck(ctx, p, art.Repository, art.Tag)
		if fresh {
			if ok, man := c.servable(ctx, a, art, dig); ok {
				log.Debugf("tag %v:%v checked inside the refresh window, digest %v", art.Repository, art.Tag, dig)
				return true, man, nil
			}
			// the cache no longer holds what the record names, so ask upstream
		}
		lastDigest = dig
	}

	exist, desc, err := remote.ManifestExist(GetRemoteRepo(art), ref) // HEAD
	switch {
	case err != nil:
		// upstream unavailable or rate limited: serve the last recorded digest, else the local copy
		if lastDigest != "" {
			if ok, man := c.servable(ctx, a, art, lastDigest); ok {
				log.Warningf("failed to check %v:%v upstream, serving the cached digest %v: %v", art.Repository, ref, lastDigest, err)
				return true, man, nil
			}
		}
		if a != nil {
			log.Warningf("failed to check %v:%v upstream, serving the cached copy: %v", art.Repository, ref, err)
			return true, nil, nil
		}
		return false, nil, err
	case !exist || desc == nil:
		c.saveMiss(ctx, p, art.Repository, ref)
		if len(art.Digest) == 0 {
			c.clearTagCheck(ctx, p, art.Repository, art.Tag)
		}
		return c.upstreamNotFound(a, p, art)
	}
	c.clearMiss(ctx, p, art.Repository, ref)
	if len(art.Digest) == 0 {
		c.saveTagCheck(ctx, p, art.Repository, art.Tag, string(desc.Digest))
	}
	ok, man := c.servable(ctx, a, art, string(desc.Digest))
	return ok, man, nil
}

// servable reports whether the cache holds dig: the original manifest list, or the local artifact itself
func (c *controller) servable(ctx context.Context, a *artifact.Artifact, art lib.ArtifactInfo, dig string) (bool, *ManifestList) {
	if c.cache != nil {
		art.Digest = dig
		var content []byte
		err := c.cache.Fetch(ctx, manifestListKey(art.Repository, art), &content)
		switch {
		case err == nil:
			var contentType string
			if err := c.cache.Fetch(ctx, manifestListContentTypeKey(art.Repository, art), &contentType); err != nil {
				log.Debugf("failed to get the manifest list content type, not use local. error:%v", err)
				return false, nil
			}
			log.Debugf("Get the manifest list with key=cache:%v", manifestListKey(art.Repository, art))
			return true, &ManifestList{content, dig, contentType}
		case errors.Is(err, cache.ErrNotFound):
			log.Debugf("Digest is not found in manifest list cache, key=cache:%v", manifestListKey(art.Repository, art))
		default:
			log.Errorf("Failed to get manifest list from cache, error: %v", err)
		}
	}
	return a != nil && a.Digest == dig, nil
}

// upstreamNotFound serves the local copy when the project keeps removed images, otherwise 404
func (c *controller) upstreamNotFound(a *artifact.Artifact, p *proModels.Project, art lib.ArtifactInfo) (bool, *ManifestList, error) {
	if a != nil && p != nil && p.ProxyCacheLocalOnNotFound() {
		log.Infof("Artifact not found in remote registry but exists in local cache, serving from local: %v:%v", art.Repository, art.Tag)
		return true, nil, nil
	}
	return false, nil, errors.NotFoundError(fmt.Errorf("repo %v, tag %v not found", art.Repository, art.Tag))
}

func manifestListKey(repo string, art lib.ArtifactInfo) string {
	// actual redis key format is cache:manifestlist:<repo name>:<tag> or cache:manifestlist:<repo name>:sha256:xxxx
	return "manifestlist:" + repo + ":" + getReference(art)
}

func manifestListContentTypeKey(rep string, art lib.ArtifactInfo) string {
	return manifestListKey(rep, art) + ":contenttype"
}

func (c *controller) ProxyManifest(ctx context.Context, art lib.ArtifactInfo, remote RemoteInterface) (distribution.Manifest, error) {
	var man distribution.Manifest
	remoteRepo := GetRemoteRepo(art)
	ref := getReference(art)
	man, dig, err := remote.Manifest(remoteRepo, ref)
	if err != nil {
		return man, err
	}
	ct, _, err := man.Payload()
	if err != nil {
		return man, err
	}

	// Push manifest to the local cache in the background, bounded by the global
	// proxy-cache concurrency limit so a slow/unresponsive backend cannot make
	// these detached goroutines accumulate without bound.
	op := operator.FromContext(ctx)
	ip, ua := requestinfo.FromContext(ctx)
	// one fill per manifest: each can wait minutes for its blobs, duplicates would take every slot
	fillKey := "manifest-fill:" + art.Repository + ":" + ref + "@" + dig
	if !startFill(fillKey, pullEvent{tag: art.Tag, op: op, ip: ip, ua: ua}) {
		return man, nil
	}
	if !GoCacheFill("manifest:"+art.Repository, func() {
		ended := false
		defer func() {
			if !ended {
				endFill(fillKey)
			}
		}()
		bCtx := orm.Copy(ctx)
		a, err := c.local.GetManifest(bCtx, art)
		if err != nil {
			log.Errorf("failed to get manifest, error %v", err)
		}
		// Push manifest to local when pull with digest, or artifact not found, or digest mismatch
		if len(art.Tag) == 0 || a == nil || a.Digest != dig {
			artInfo := art
			if len(artInfo.Digest) == 0 {
				artInfo.Digest = dig
			}
			c.waitAndPushManifest(bCtx, remoteRepo, man, artInfo, ct, remote)
		}

		// Query artifact after push
		if a == nil {
			a, err = c.local.GetManifest(bCtx, art)
			if err != nil {
				log.Errorf("failed to get manifest, error %v", err)
			}
		}
		parked := endFill(fillKey)
		ended = true
		if a != nil {
			SendPullEvent(bCtx, a, art.Tag, op, ip, ua)
			for _, e := range parked {
				SendPullEvent(bCtx, a, e.tag, e.op, e.ip, e.ua)
			}
		}
	}) {
		parked := endFill(fillKey)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					log.Errorf("proxy-cache pull event task for %q panicked: %v", art.Repository, r)
				}
			}()
			c.sendManifestPullEvent(orm.Copy(ctx), art, op)
			if len(parked) > 0 {
				c.sendParkedPullEvents(orm.Copy(ctx), art, parked)
			}
		}()
	}

	return man, nil
}

func (c *controller) sendParkedPullEvents(ctx context.Context, art lib.ArtifactInfo, events []pullEvent) {
	a, err := c.local.GetManifest(ctx, art)
	if err != nil || a == nil {
		return
	}
	for _, e := range events {
		SendPullEvent(ctx, a, e.tag, e.op, e.ip, e.ua)
	}
}

func (c *controller) sendManifestPullEvent(ctx context.Context, art lib.ArtifactInfo, op string) {
	a, err := c.local.GetManifest(ctx, art)
	if err != nil {
		log.Errorf("failed to get manifest, error %v", err)
	}
	if a != nil {
		ip, ua := requestinfo.FromContext(ctx)
		SendPullEvent(ctx, a, art.Tag, op, ip, ua)
	}
}

func (c *controller) HeadManifest(_ context.Context, art lib.ArtifactInfo, remote RemoteInterface) (bool, *distribution.Descriptor, error) {
	remoteRepo := GetRemoteRepo(art)
	ref := getReference(art)
	return remote.ManifestExist(remoteRepo, ref)
}

func (c *controller) ProxyBlob(ctx context.Context, p *proModels.Project, art lib.ArtifactInfo) (int64, io.ReadCloser, error) {
	remoteRepo := GetRemoteRepo(art)
	log.Debugf("The blob doesn't exist, proxy the request to the target server, url:%v", remoteRepo)
	rHelper, err := NewRemoteHelper(ctx, p.RegistryID, WithSpeed(p.ProxyCacheSpeed()))
	if err != nil {
		return 0, nil, err
	}

	size, bReader, err := rHelper.BlobReader(remoteRepo, art.Digest)
	if err != nil {
		log.Errorf("failed to pull blob, error %v", err)
		return 0, nil, err
	}
	desc := distribution.Descriptor{Size: size, Digest: digest.Digest(art.Digest)}
	// Populate the local cache in the background, bounded by the global
	// proxy-cache concurrency limit (see GoCacheFill).
	GoCacheFill("blob:"+art.Repository, func() {
		if err := c.putBlobToLocal(remoteRepo, art.Repository, desc, rHelper); err != nil {
			log.Errorf("error while putting blob to local repo, %v", err)
		}
	})
	return size, bReader, nil
}

func (c *controller) putBlobToLocal(remoteRepo string, localRepo string, desc distribution.Descriptor, r RemoteInterface) error {
	log.Debugf("Put blob to local registry!, sourceRepo:%v, localRepo:%v, digest: %v", remoteRepo, localRepo, desc.Digest)
	_, bReader, err := r.BlobReader(remoteRepo, string(desc.Digest))
	if err != nil {
		log.Errorf("failed to create blob reader, error %v", err)
		return err
	}
	defer bReader.Close()
	err = c.local.PushBlob(localRepo, desc, bReader)
	return err
}

func (c *controller) waitAndPushManifest(ctx context.Context, remoteRepo string, man distribution.Manifest, art lib.ArtifactInfo, contType string, r RemoteInterface) {
	h, ok := c.handlerRegistry[contType]
	if !ok {
		h, ok = c.handlerRegistry[defaultHandler]
		if !ok {
			return
		}
	}
	h.CacheContent(ctx, remoteRepo, man, art, r, contType)
}

// GetRemoteRepo get the remote repository name, used in proxy cache
func GetRemoteRepo(art lib.ArtifactInfo) string {
	return strings.TrimPrefix(art.Repository, art.ProjectName+"/")
}

func getReference(art lib.ArtifactInfo) string {
	if len(art.Digest) > 0 {
		return art.Digest
	}
	return art.Tag
}
