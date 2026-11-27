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
	"fmt"
	"strconv"
	"time"

	"github.com/goharbor/harbor/src/lib/log"
)

const (
	// DefaultProxyCacheRefreshMinutes is how long a checked tag is served without asking upstream.
	DefaultProxyCacheRefreshMinutes = 1440
	// DefaultProxyCacheMissMinutes is how long an upstream 404 is remembered.
	DefaultProxyCacheMissMinutes = 10
	// MinProxyCacheMissMinutes and MaxProxyCacheMissMinutes bound the miss duration.
	MinProxyCacheMissMinutes = 5
	MaxProxyCacheMissMinutes = 30
	// MaxProxyCacheRefreshMinutes is one year, far below the time.Duration limit.
	MaxProxyCacheRefreshMinutes = 525600
	// ProxyCacheNeverRecheck keeps a record until it is overwritten.
	ProxyCacheNeverRecheck = -1
)

// CacheWindow is a proxy cache duration. Never means the record never expires.
type CacheWindow struct {
	Never    bool
	Duration time.Duration
}

// Fresh reports whether a record checked at checkedAt is still inside the window.
func (w CacheWindow) Fresh(checkedAt, now time.Time) bool {
	return w.Never || now.Sub(checkedAt) < w.Duration
}

// TTL is the store expiration for a record, 0 means no expiration.
func (w CacheWindow) TTL() time.Duration {
	if w.Never {
		return 0
	}
	return w.Duration
}

// ProxyCacheRefreshWindow returns the tag refresh window of a proxy cache project.
func (p *Project) ProxyCacheRefreshWindow() CacheWindow {
	return p.cacheWindow(ProMetaProxyCacheRefreshDuration, DefaultProxyCacheRefreshMinutes)
}

// ProxyCacheMissWindow returns how long an upstream 404 is remembered.
func (p *Project) ProxyCacheMissWindow() CacheWindow {
	return p.cacheWindow(ProMetaProxyCacheMissDuration, DefaultProxyCacheMissMinutes)
}

func (p *Project) cacheWindow(key string, defaultMinutes int64) CacheWindow {
	minutes := defaultMinutes
	if val, ok := p.GetMetadata(key); ok && val != "" {
		v, err := ParseProxyCacheDuration(key, val)
		if err != nil {
			log.Warningf("project %s: %v, using default %d", p.Name, err, defaultMinutes)
		} else {
			minutes = v
		}
	}
	if minutes == ProxyCacheNeverRecheck {
		return CacheWindow{Never: true}
	}
	return CacheWindow{Duration: time.Duration(minutes) * time.Minute}
}

// ParseProxyCacheDuration validates a refresh or miss duration in minutes.
func ParseProxyCacheDuration(key, value string) (int64, error) {
	v, err := strconv.ParseInt(value, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%s should be an integer number of minutes, got %q", key, value)
	}
	if v == ProxyCacheNeverRecheck {
		return v, nil
	}
	switch key {
	case ProMetaProxyCacheMissDuration:
		if v < MinProxyCacheMissMinutes || v > MaxProxyCacheMissMinutes {
			return 0, fmt.Errorf("%s should be -1 or between %d and %d minutes, got %d", key, MinProxyCacheMissMinutes, MaxProxyCacheMissMinutes, v)
		}
	default:
		if v < 1 || v > MaxProxyCacheRefreshMinutes {
			return 0, fmt.Errorf("%s should be -1 or between 1 and %d minutes, got %d", key, MaxProxyCacheRefreshMinutes, v)
		}
	}
	return v, nil
}
