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

import "context"

type deletedRepositoriesKey struct{}

// WithDeletedRepositories marks the repositories one request deletes; the
// artifacts removed with them are covered by the repository's own entry.
func WithDeletedRepositories(ctx context.Context, repositories []string) context.Context {
	if len(repositories) == 0 {
		return ctx
	}
	set := make(map[string]struct{}, len(repositories))
	for _, r := range repositories {
		set[r] = struct{}{}
	}
	return context.WithValue(ctx, deletedRepositoriesKey{}, set)
}

// RepositoryDeleted reports whether the request behind ctx deletes repository.
func RepositoryDeleted(ctx context.Context, repository string) bool {
	set, _ := ctx.Value(deletedRepositoriesKey{}).(map[string]struct{})
	_, ok := set[repository]
	return ok
}
