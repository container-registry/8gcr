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
	"strconv"
	"sync"
	"time"
)

const (
	// IndexMemberTTL bounds how long an index push hides the platform
	// manifests it lists.
	IndexMemberTTL = 10 * time.Minute
	maxEntries     = 50000
)

// IndexMembers records the manifests listed by indexes pushed recently.
var IndexMembers = NewWindow(IndexMemberTTL, maxEntries)

// markMu orders marks, so a later mark never carries an older time.
var markMu sync.Mutex

// MarkIndexMembers records that operator pushed an index to repo listing the
// manifests in its body.
func MarkIndexMembers(repo, operator string, index []byte) {
	children := IndexChildren(index)
	markMu.Lock()
	defer markMu.Unlock()
	marked := strconv.FormatInt(IndexMembers.now().UnixNano(), 10)
	for _, d := range children {
		IndexMembers.Put(memberKey(repo, operator, d), marked)
	}
}

// IsIndexMember reports whether operator pushed, at or after pushedAt, an
// index to repo that lists digest. An older index, or one pushed by someone
// else, never covers a push.
func IsIndexMember(repo, operator, digest string, pushedAt time.Time) bool {
	marked, ok := IndexMembers.Get(memberKey(repo, operator, digest))
	if !ok {
		return false
	}
	nanos, err := strconv.ParseInt(marked, 10, 64)
	return err == nil && !time.Unix(0, nanos).Before(pushedAt)
}

// memberKey keeps each operator's coverage apart, so another operator's
// index never replaces it.
func memberKey(repo, operator, digest string) string {
	return repo + "@" + digest + "\x00" + operator
}
