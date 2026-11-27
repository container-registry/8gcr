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

	"github.com/docker/distribution"
	"github.com/stretchr/testify/require"

	testproxy "github.com/goharbor/harbor/src/testing/controller/proxy"
)

func TestLazyRemoteBuildsOnFirstCallOnly(t *testing.T) {
	inner := &testproxy.RemoteInterface{}
	inner.On("ManifestExist", "library/nginx", "latest").Return(true, &distribution.Descriptor{}, nil)
	inner.On("ListTags", "library/nginx").Return([]string{"latest"}, nil)
	built := 0
	l := &lazyRemote{build: func() (RemoteInterface, error) { built++; return inner, nil }}
	require.Equal(t, 0, built, "nothing is built before the first upstream call")

	exist, _, err := l.ManifestExist("library/nginx", "latest")
	require.NoError(t, err)
	require.True(t, exist)
	tags, err := l.ListTags("library/nginx")
	require.NoError(t, err)
	require.Equal(t, []string{"latest"}, tags)
	require.Equal(t, 1, built)
	inner.AssertExpectations(t)
}

func TestLazyRemoteReturnsBuildError(t *testing.T) {
	built := 0
	l := &lazyRemote{build: func() (RemoteInterface, error) { built++; return nil, context.Canceled }}
	_, _, err := l.ManifestExist("library/nginx", "latest")
	require.ErrorIs(t, err, context.Canceled)
	_, _, err = l.Manifest("library/nginx", "latest")
	require.ErrorIs(t, err, context.Canceled)
	_, _, err = l.BlobReader("library/nginx", "sha256:x")
	require.ErrorIs(t, err, context.Canceled)
	_, _, err = l.ListReferrers("library/nginx", "sha256:x", "")
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, 1, built)
}

