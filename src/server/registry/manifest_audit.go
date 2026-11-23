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

package registry

import (
	"net/http"
	"time"

	"github.com/opencontainers/go-digest"

	"github.com/goharbor/harbor/src/common"
	"github.com/goharbor/harbor/src/controller/event/operator"
	"github.com/goharbor/harbor/src/pkg/artifact"
	"github.com/goharbor/harbor/src/pkg/auditext/collapse"
	securitymiddleware "github.com/goharbor/harbor/src/server/middleware/security"
)

const (
	// pullWindowTTL bounds how long a tag HEAD or an index GET shapes the
	// audit of the manifest requests that follow it in the same pull.
	pullWindowTTL = time.Minute
	// pullWindowMaxEntries caps the memory the window may hold.
	pullWindowMaxEntries = 50000
)

// pulls collapses one client pull into one audit entry.
var pulls = collapse.NewWindow(pullWindowTTL, pullWindowMaxEntries)

// auditPull decides whether a successful manifest request fires a pull event.
// Docker and containerd resolve a tag with HEAD and then GET the digest, so
// the tag from that HEAD is handed back for the GET. A platform manifest
// fetched after its index GET still fires the event (webhooks, pull time),
// but marks the request so the audit handler does not log it twice.
func auditPull(req *http.Request, art *artifact.Artifact, reference string, body []byte) (tag string, audit bool) {
	if req.UserAgent() == common.UserAgent {
		return "", false
	}
	client := operator.FromContext(req.Context()) + "|" + securitymiddleware.GetClientIP(req) + "|" + art.RepositoryName
	_, byDigest := digest.Parse(reference)
	byTag := byDigest != nil

	if req.Method == http.MethodHead {
		if byTag {
			pulls.Put(client+"|tag|"+art.Digest, reference)
		}
		return "", false
	}
	if !byTag {
		if _, ok := pulls.Get(client + "|child|" + art.Digest); ok {
			collapse.SkipPullAudit(req.Context())
		}
		// the hint belongs to the one GET that follows its HEAD
		tag, _ = pulls.Take(client + "|tag|" + art.Digest)
	} else {
		// a GET by tag carries its tag; drop the hint so a later digest pull
		// does not inherit it
		pulls.Take(client + "|tag|" + art.Digest)
	}
	if art.IsImageIndex() {
		for _, child := range collapse.IndexChildren(body) {
			pulls.Put(client+"|child|"+child, "")
		}
	}
	return tag, true
}
