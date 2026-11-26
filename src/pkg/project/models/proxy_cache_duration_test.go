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

package models

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestParseProxyCacheDuration(t *testing.T) {
	cases := []struct {
		key, value string
		want       int64
		wantErr    bool
	}{
		{ProMetaProxyCacheRefreshDuration, "-1", -1, false},
		{ProMetaProxyCacheRefreshDuration, "1", 1, false},
		{ProMetaProxyCacheRefreshDuration, "1440", 1440, false},
		{ProMetaProxyCacheRefreshDuration, "525600", 525600, false},
		{ProMetaProxyCacheRefreshDuration, "525601", 0, true},
		{ProMetaProxyCacheRefreshDuration, "2147483647", 0, true},
		{ProMetaProxyCacheRefreshDuration, "0", 0, true},
		{ProMetaProxyCacheRefreshDuration, "-2", 0, true},
		{ProMetaProxyCacheRefreshDuration, "1.5", 0, true},
		{ProMetaProxyCacheRefreshDuration, "", 0, true},
		{ProMetaProxyCacheMissDuration, "-1", -1, false},
		{ProMetaProxyCacheMissDuration, "5", 5, false},
		{ProMetaProxyCacheMissDuration, "30", 30, false},
		{ProMetaProxyCacheMissDuration, "0", 0, true},
		{ProMetaProxyCacheMissDuration, "4", 0, true},
		{ProMetaProxyCacheMissDuration, "31", 0, true},
	}
	for _, c := range cases {
		got, err := ParseProxyCacheDuration(c.key, c.value)
		if c.wantErr {
			assert.Error(t, err, "%s=%q", c.key, c.value)
			continue
		}
		assert.NoError(t, err, "%s=%q", c.key, c.value)
		assert.Equal(t, c.want, got)
	}
}

func TestProxyCacheWindows(t *testing.T) {
	p := &Project{}
	assert.Equal(t, CacheWindow{Duration: 24 * time.Hour}, p.ProxyCacheRefreshWindow())
	assert.Equal(t, CacheWindow{Duration: 10 * time.Minute}, p.ProxyCacheMissWindow())

	p.Metadata = map[string]string{
		ProMetaProxyCacheRefreshDuration: "-1",
		ProMetaProxyCacheMissDuration:    "30",
	}
	assert.Equal(t, CacheWindow{Never: true}, p.ProxyCacheRefreshWindow())
	assert.Equal(t, CacheWindow{Duration: 30 * time.Minute}, p.ProxyCacheMissWindow())

	checked := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	w := CacheWindow{Duration: time.Minute}
	assert.True(t, w.Fresh(checked, checked.Add(59*time.Second)))
	assert.False(t, w.Fresh(checked, checked.Add(time.Minute)))
	assert.Equal(t, time.Minute, w.TTL())
	assert.True(t, CacheWindow{Never: true}.Fresh(checked, checked.Add(1000*time.Hour)))
	assert.Equal(t, time.Duration(0), CacheWindow{Never: true}.TTL())
}
