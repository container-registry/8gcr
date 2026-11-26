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
	"encoding/json"
	"sync"
	"time"
)

// IndexChildren returns the manifest digests an OCI index or Docker manifest list names.
func IndexChildren(body []byte) []string {
	var index struct {
		Manifests []struct {
			Digest string `json:"digest"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal(body, &index); err != nil {
		return nil
	}
	children := make([]string, 0, len(index.Manifests))
	for _, m := range index.Manifests {
		if m.Digest != "" {
			children = append(children, m.Digest)
		}
	}
	return children
}

type entry struct {
	value   string
	expires time.Time
}

// Window is a bounded map whose entries expire after a fixed TTL. It is per
// core instance: with several replicas a platform manifest may still be
// audited on its own, but no entry is dropped.
type Window struct {
	mu      sync.Mutex
	ttl     time.Duration
	max     int
	now     func() time.Time
	entries map[string]entry
}

// NewWindow returns a Window holding at most maxEntries keys for ttl each.
func NewWindow(ttl time.Duration, maxEntries int) *Window {
	return &Window{ttl: ttl, max: maxEntries, now: time.Now, entries: map[string]entry{}}
}

// Put stores value under key for the window's TTL.
func (w *Window) Put(key, value string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := w.now()
	if _, exists := w.entries[key]; !exists && len(w.entries) >= w.max {
		for k, e := range w.entries {
			if now.After(e.expires) {
				delete(w.entries, k)
			}
		}
		if len(w.entries) >= w.max {
			// a flood of distinct keys costs a few extra audit rows, never memory
			clear(w.entries)
		}
	}
	w.entries[key] = entry{value: value, expires: now.Add(w.ttl)}
}

// Get returns the live value under key.
func (w *Window) Get(key string) (string, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	e, ok := w.entries[key]
	if !ok {
		return "", false
	}
	if w.now().After(e.expires) {
		delete(w.entries, key)
		return "", false
	}
	return e.value, true
}

// Take returns the live value under key and removes it, so it is used once.
func (w *Window) Take(key string) (string, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	e, ok := w.entries[key]
	if !ok {
		return "", false
	}
	delete(w.entries, key)
	if w.now().After(e.expires) {
		return "", false
	}
	return e.value, true
}
