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
	"sync"

	"github.com/docker/distribution"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/goharbor/harbor/src/lib"
	"github.com/goharbor/harbor/src/pkg/reg"
	"github.com/goharbor/harbor/src/pkg/reg/adapter"
	"github.com/goharbor/harbor/src/pkg/reg/model"
)

// RemoteInterface defines operations related to remote repository under proxy
type RemoteInterface interface {
	// BlobReader create a reader for remote blob
	BlobReader(repo, dig string) (int64, io.ReadCloser, error)
	// Manifest get manifest by reference
	Manifest(repo string, ref string) (distribution.Manifest, string, error)
	// ManifestExist checks manifest exist, if exist, returns digest
	ManifestExist(repo string, ref string) (bool, *distribution.Descriptor, error)
	// ListTags returns all tags of the repo
	ListTags(repo string) ([]string, error)
	// ListReferrers returns all referrers
	ListReferrers(repo string, digest string, rawQuery string) (*ocispec.Index, map[string][]string, error)
}

// remoteHelper defines operations related to remote repository under proxy
type remoteHelper struct {
	regID       int64
	registry    adapter.ArtifactRegistry
	registryMgr reg.Manager
	opts        *Options
}

// NewRemoteHelper create a remote interface
func NewRemoteHelper(ctx context.Context, regID int64, opts ...Option) (RemoteInterface, error) {
	r := &remoteHelper{
		regID:       regID,
		registryMgr: reg.Mgr,
		opts:        NewOptions(opts...),
	}
	if err := r.init(ctx); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *remoteHelper) init(ctx context.Context) error {
	if r.registry != nil {
		return nil
	}
	reg, err := r.registryMgr.Get(ctx, r.regID)
	if err != nil {
		return err
	}
	if reg == nil {
		return fmt.Errorf("failed to get registry, registryID: %v", r.regID)
	}
	if reg.Status != model.Healthy {
		return fmt.Errorf("current registry is unhealthy, regID:%v, Name:%v, Status: %v", reg.ID, reg.Name, reg.Status)
	}
	factory, err := adapter.GetFactory(reg.Type)
	if err != nil {
		return err
	}
	adp, err := factory.Create(reg)
	if err != nil {
		return err
	}
	r.registry = adp.(adapter.ArtifactRegistry)
	return nil
}

func (r *remoteHelper) BlobReader(repo, dig string) (int64, io.ReadCloser, error) {
	sz, bReader, err := r.registry.PullBlob(repo, dig)
	if err != nil {
		return 0, nil, err
	}
	if r.opts != nil && r.opts.Speed > 0 {
		bReader = lib.NewReader(bReader, r.opts.Speed)
	}
	return sz, bReader, err
}

func (r *remoteHelper) Manifest(repo string, ref string) (distribution.Manifest, string, error) {
	return r.registry.PullManifest(repo, ref)
}

func (r *remoteHelper) ManifestExist(repo string, ref string) (bool, *distribution.Descriptor, error) {
	return r.registry.ManifestExist(repo, ref)
}

func (r *remoteHelper) ListTags(repo string) ([]string, error) {
	return r.registry.ListTags(repo)
}

func (r *remoteHelper) ListReferrers(repo string, digest string, rawQuery string) (*ocispec.Index, map[string][]string, error) {
	return r.registry.ListReferrers(repo, digest, rawQuery)
}

// NewLazyRemoteHelper builds the remote on its first call, so a pull served from the cache makes no
// upstream request (the Docker Hub adapter logs in when it is created)
func NewLazyRemoteHelper(ctx context.Context, regID int64, opts ...Option) RemoteInterface {
	return &lazyRemote{build: func() (RemoteInterface, error) { return NewRemoteHelper(ctx, regID, opts...) }}
}

type lazyRemote struct {
	build  func() (RemoteInterface, error)
	once   sync.Once
	remote RemoteInterface
	err    error
}

func (l *lazyRemote) get() (RemoteInterface, error) {
	l.once.Do(func() {
		l.remote, l.err = l.build()
	})
	return l.remote, l.err
}

func (l *lazyRemote) BlobReader(repo, dig string) (int64, io.ReadCloser, error) {
	r, err := l.get()
	if err != nil {
		return 0, nil, err
	}
	return r.BlobReader(repo, dig)
}

func (l *lazyRemote) Manifest(repo string, ref string) (distribution.Manifest, string, error) {
	r, err := l.get()
	if err != nil {
		return nil, "", err
	}
	return r.Manifest(repo, ref)
}

func (l *lazyRemote) ManifestExist(repo string, ref string) (bool, *distribution.Descriptor, error) {
	r, err := l.get()
	if err != nil {
		return false, nil, err
	}
	return r.ManifestExist(repo, ref)
}

func (l *lazyRemote) ListTags(repo string) ([]string, error) {
	r, err := l.get()
	if err != nil {
		return nil, err
	}
	return r.ListTags(repo)
}

func (l *lazyRemote) ListReferrers(repo string, digest string, rawQuery string) (*ocispec.Index, map[string][]string, error) {
	r, err := l.get()
	if err != nil {
		return nil, nil, err
	}
	return r.ListReferrers(repo, digest, rawQuery)
}
