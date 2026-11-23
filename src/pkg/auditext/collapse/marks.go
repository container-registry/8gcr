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
	"sync/atomic"
)

type requestMarksKey struct{}

// RequestMarks carries audit decisions made while serving a request to the
// audit handler, which sees the events after the response is written.
type RequestMarks struct {
	skipPull atomic.Bool
}

// NewRequestMarks returns empty marks for a request.
func NewRequestMarks() *RequestMarks {
	return &RequestMarks{}
}

// Into returns ctx carrying the marks.
func (m *RequestMarks) Into(ctx context.Context) context.Context {
	return context.WithValue(ctx, requestMarksKey{}, m)
}

// SkipPullAudit records that the pull served by this request is part of an
// operation already audited. The pull event itself is still published.
func SkipPullAudit(ctx context.Context) {
	if m, ok := ctx.Value(requestMarksKey{}).(*RequestMarks); ok {
		m.skipPull.Store(true)
	}
}

// PullAuditSkipped reports whether the request behind ctx asked to skip its pull audit.
func PullAuditSkipped(ctx context.Context) bool {
	m, ok := ctx.Value(requestMarksKey{}).(*RequestMarks)
	return ok && m.skipPull.Load()
}
