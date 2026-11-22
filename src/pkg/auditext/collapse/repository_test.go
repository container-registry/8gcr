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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDeletedRepositories(t *testing.T) {
	ctx := context.Background()
	assert.False(t, RepositoryDeleted(ctx, "lib/app"))
	assert.Equal(t, ctx, WithDeletedRepositories(ctx, nil))
	ctx = WithDeletedRepositories(ctx, []string{"lib/app"})
	assert.True(t, RepositoryDeleted(ctx, "lib/app"))
	assert.False(t, RepositoryDeleted(ctx, "lib/other"))
}
