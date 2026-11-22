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

package collapse

import (
	"context"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestIndexMembers(t *testing.T) {
	index := []byte(`{"schemaVersion":2,"manifests":[{"digest":"sha256:aa"},{"digest":"sha256:bb"},{"mediaType":"x"}]}`)
	pushed := time.Now().Add(-time.Second)
	MarkIndexMembers("lib/app", "alice", index)
	assert.True(t, IsIndexMember("lib/app", "alice", "sha256:aa", pushed))
	assert.False(t, IsIndexMember("lib/other", "alice", "sha256:aa", pushed))
	assert.False(t, IsIndexMember("lib/app", "alice", "sha256:cc", pushed))
	assert.False(t, IsIndexMember("lib/app", "bob", "sha256:aa", pushed), "another user's index covers nothing")
	MarkIndexMembers("lib/app", "bob", index)
	assert.True(t, IsIndexMember("lib/app", "alice", "sha256:aa", pushed), "bob's index does not replace alice's coverage")
	assert.False(t, IsIndexMember("lib/app", "alice", "sha256:aa", time.Now().Add(time.Second)), "an older index never covers a later push")
}

func TestRequestStarted(t *testing.T) {
	_, ok := RequestStarted(context.Background())
	assert.False(t, ok)
	_, ok = RequestStarted((&RequestMarks{}).Into(context.Background()))
	assert.False(t, ok, "marks not made by NewRequestMarks have no start")
	started, ok := RequestStarted(NewRequestMarks().Into(context.Background()))
	assert.True(t, ok)
	assert.WithinDuration(t, time.Now(), started, time.Second)
}

func TestIndexMarkNeverMovesBack(t *testing.T) {
	var tick atomic.Int64
	base := time.Now()
	old := IndexMembers.now
	IndexMembers.now = func() time.Time {
		n := tick.Add(1)
		time.Sleep(time.Millisecond)
		return base.Add(time.Duration(n))
	}
	t.Cleanup(func() { IndexMembers.now = old })

	index := []byte(`{"manifests":[{"digest":"sha256:race"}]}`)
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			MarkIndexMembers("lib/race", "alice", index)
		}()
	}
	wg.Wait()
	// each mark reads the clock once for its time and once in Put
	newest := base.Add(time.Duration(tick.Load() - 1)).UnixNano()
	marked, _ := IndexMembers.entries[memberKey("lib/race", "alice", "sha256:race")]
	assert.Equal(t, strconv.FormatInt(newest, 10), marked.value)
}
