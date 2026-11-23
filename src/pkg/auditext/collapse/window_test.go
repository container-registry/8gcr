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
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestWindowExpires(t *testing.T) {
	now := time.Unix(1000, 0)
	w := NewWindow(time.Minute, 10)
	w.now = func() time.Time { return now }
	w.Put("k", "v")
	v, ok := w.Get("k")
	assert.True(t, ok)
	assert.Equal(t, "v", v)
	now = now.Add(2 * time.Minute)
	_, ok = w.Get("k")
	assert.False(t, ok)
}

func TestWindowTakeIsOnce(t *testing.T) {
	w := NewWindow(time.Minute, 10)
	w.Put("k", "v")
	v, ok := w.Take("k")
	assert.True(t, ok)
	assert.Equal(t, "v", v)
	_, ok = w.Take("k")
	assert.False(t, ok)
	_, ok = w.Get("k")
	assert.False(t, ok)
}

func TestWindowIsBounded(t *testing.T) {
	w := NewWindow(time.Hour, 5)
	for i := range 100 {
		w.Put(fmt.Sprint(i), "")
		assert.LessOrEqual(t, len(w.entries), 5)
	}
	_, ok := w.Get("99")
	assert.True(t, ok)
}

func TestWindowRefreshAtCapacityKeepsOtherKeys(t *testing.T) {
	w := NewWindow(time.Hour, 3)
	w.Put("a", "")
	w.Put("b", "")
	w.Put("c", "")
	w.Put("a", "again")
	for _, k := range []string{"a", "b", "c"} {
		_, ok := w.Get(k)
		assert.True(t, ok, k)
	}
}

func TestIndexChildren(t *testing.T) {
	index := []byte(`{"schemaVersion":2,"manifests":[{"digest":"sha256:aa"},{"digest":"sha256:bb"},{"mediaType":"x"}]}`)
	assert.Equal(t, []string{"sha256:aa", "sha256:bb"}, IndexChildren(index))
	assert.Nil(t, IndexChildren([]byte("not json")))
}
