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

//go:build !db

package auditlog

import (
	"testing"
	"time"

	"github.com/goharbor/harbor/src/controller/event"
	"github.com/goharbor/harbor/src/pkg/artifact"
	"github.com/goharbor/harbor/src/pkg/auditext"
	testingauditext "github.com/goharbor/harbor/src/testing/pkg/auditext"
)

// mockManager swaps the audit log manager for a mock until the test ends.
func mockManager(t *testing.T) *testingauditext.Manager {
	t.Helper()
	mgr := &testingauditext.Manager{}
	orig := auditext.Mgr
	auditext.Mgr = mgr
	t.Cleanup(func() { auditext.Mgr = orig })
	return mgr
}

func artifactEvent(repo, digest string) *event.ArtifactEvent {
	return &event.ArtifactEvent{
		Repository: repo,
		Operator:   "alice",
		OccurAt:    time.Now(),
		Artifact:   &artifact.Artifact{RepositoryName: repo, Digest: digest, ManifestMediaType: "application/vnd.oci.image.manifest.v1+json"},
	}
}
