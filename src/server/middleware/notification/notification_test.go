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

package notification

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/goharbor/harbor/src/controller/event/metadata"
	"github.com/goharbor/harbor/src/pkg/artifact"
	"github.com/goharbor/harbor/src/pkg/auditext/collapse"
	"github.com/goharbor/harbor/src/pkg/notification"
	"github.com/goharbor/harbor/src/pkg/notifier/event"
)

type NotificationMiddlewareTestSuite struct {
	suite.Suite
}

func (suite *NotificationMiddlewareTestSuite) TestMiddleware() {
	next := func() http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusAccepted)
			notification.AddEvent(r.Context(), &metadata.DeleteArtifactEventMetadata{
				Ctx: context.Background(),
				Artifact: &artifact.Artifact{
					ProjectID:      1,
					RepositoryID:   2,
					RepositoryName: "library/hello-world",
				},
				Tags: []string{"latest"},
			})
		})
	}
	path := fmt.Sprintf("/v2/library/photon/manifests/latest")
	req := httptest.NewRequest(http.MethodPatch, path, nil)
	res := httptest.NewRecorder()
	Middleware()(next()).ServeHTTP(res, req)
	suite.Equal(http.StatusAccepted, res.Code)
}

func (suite *NotificationMiddlewareTestSuite) TestMiddlewareMustNotify() {
	next := func() http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			notification.AddEvent(r.Context(), &metadata.DeleteArtifactEventMetadata{
				Ctx: context.Background(),
				Artifact: &artifact.Artifact{
					ProjectID:      1,
					RepositoryID:   2,
					RepositoryName: "library/hello-world",
				},
				Tags: []string{"latest"},
			}, true)
		})
	}
	path := fmt.Sprintf("/v2/library/photon/manifests/latest")
	req := httptest.NewRequest(http.MethodPatch, path, nil)
	res := httptest.NewRecorder()
	Middleware()(next()).ServeHTTP(res, req)
	suite.Equal(http.StatusInternalServerError, res.Code)
}

func (suite *NotificationMiddlewareTestSuite) TestDeletedRepositories() {
	evc := notification.NewEventCtx()
	evc.Events.PushBack(&metadata.DeleteArtifactEventMetadata{Artifact: &artifact.Artifact{RepositoryName: "library/gone"}})
	suite.Empty(deletedRepositories(evc), "an artifact delete alone marks nothing")

	evc.Events.PushBack(&metadata.DeleteRepositoryEventMetadata{Repository: "library/gone"})
	suite.Equal([]string{"library/gone"}, deletedRepositories(evc))
}

func (suite *NotificationMiddlewareTestSuite) TestMiddlewareMarksDeletedRepositories() {
	var published []context.Context
	orig := publish
	publish = func(ctx context.Context, _ ...event.Metadata) { published = append(published, ctx) }
	defer func() { publish = orig }()

	serve := func(withRepository bool) []context.Context {
		published = nil
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			notification.AddEvent(r.Context(), &metadata.DeleteArtifactEventMetadata{
				Ctx: context.Background(), Artifact: &artifact.Artifact{RepositoryName: "library/gone"}})
			if withRepository {
				notification.AddEvent(r.Context(), &metadata.DeleteRepositoryEventMetadata{
					Ctx: context.Background(), Repository: "library/gone"})
			}
			w.WriteHeader(http.StatusOK)
		})
		Middleware()(next).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodDelete, "/api/v2.0/projects/library/repositories/gone", nil))
		return published
	}
	both := serve(true)
	suite.Len(both, 2)
	for _, ctx := range both {
		suite.True(collapse.RepositoryDeleted(ctx, "library/gone"))
	}
	got := serve(false)
	suite.Len(got, 1)
	suite.False(collapse.RepositoryDeleted(got[0], "library/gone"), "an artifact-only request marks nothing")
}

func TestNotificationMiddlewareTestSuite(t *testing.T) {
	suite.Run(t, &NotificationMiddlewareTestSuite{})
}
