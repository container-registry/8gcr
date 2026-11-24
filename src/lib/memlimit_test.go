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

package lib

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseCgroupMemoryLimit(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    int64
		wantErr bool
	}{
		{name: "v2 unlimited", in: "max\n", want: 0},
		{name: "v2 limit", in: "536870912\n", want: 536870912},
		{name: "v1 unlimited", in: "9223372036854771712\n", want: 0},
		{name: "zero", in: "0", want: 0},
		{name: "garbage", in: "lots", wantErr: true},
		{name: "empty", in: "", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseCgroupMemoryLimit(tc.in)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestCgroupMemoryLimit(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing")
	v1 := filepath.Join(dir, "memory.limit_in_bytes")
	require.NoError(t, os.WriteFile(v1, []byte("1073741824\n"), 0o600))

	got, err := cgroupMemoryLimit(missing)
	require.NoError(t, err)
	assert.Zero(t, got, "no cgroup file means no limit")

	got, err = cgroupMemoryLimit(missing, v1)
	require.NoError(t, err)
	assert.Equal(t, int64(1073741824), got, "falls back to the next file")
}

func TestCgroupV2MemoryLimit(t *testing.T) {
	// setup builds root (unlimited) > kubepods/pod1 (1Gi) > ctr (leafMax).
	setup := func(t *testing.T, leafMax, selfCgroup string) (root, leaf, self string) {
		root = t.TempDir()
		leaf = filepath.Join(root, "kubepods", "pod1", "ctr")
		require.NoError(t, os.MkdirAll(leaf, 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(root, "memory.max"), []byte("max\n"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(root, "kubepods", "pod1", "memory.max"), []byte("1073741824\n"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(leaf, "memory.max"), []byte(leafMax), 0o600))
		self = filepath.Join(t.TempDir(), "cgroup")
		require.NoError(t, os.WriteFile(self, []byte(selfCgroup), 0o600))
		return root, leaf, self
	}

	t.Run("own cgroup namespace", func(t *testing.T) {
		_, leaf, self := setup(t, "536870912\n", "0::/\n")
		got, err := cgroupV2MemoryLimit(leaf, self)
		require.NoError(t, err)
		assert.Equal(t, int64(536870912), got)
	})
	t.Run("host namespace, unlimited root, limited descendant", func(t *testing.T) {
		root, _, self := setup(t, "536870912\n", "0::/kubepods/pod1/ctr\n")
		got, err := cgroupV2MemoryLimit(root, self)
		require.NoError(t, err)
		assert.Equal(t, int64(536870912), got)
	})
	t.Run("ancestor lower than leaf", func(t *testing.T) {
		root, _, self := setup(t, "max\n", "0::/kubepods/pod1/ctr\n")
		got, err := cgroupV2MemoryLimit(root, self)
		require.NoError(t, err)
		assert.Equal(t, int64(1073741824), got)
	})
	t.Run("no cgroup files", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "none")
		got, err := cgroupV2MemoryLimit(missing, missing)
		require.NoError(t, err)
		assert.Zero(t, got)
	})
}
