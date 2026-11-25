//go:build db

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

package drift

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/goharbor/harbor/src/lib/orm"
	"github.com/goharbor/harbor/src/pkg/scan/dao/scan"
	"github.com/goharbor/harbor/src/pkg/scan/dao/scanner"
	"github.com/goharbor/harbor/src/pkg/scan/postprocessors"
	"github.com/goharbor/harbor/src/pkg/scan/report"
	v1 "github.com/goharbor/harbor/src/pkg/scan/rest/v1"
)

// cleanupFunc deletes vulnerability records no report links to. It is nil until that cleanup
// exists; the cleanup step then does nothing and the golden files record the records it leaves.
var cleanupFunc func(ctx context.Context) error

type artifactRow struct {
	label   string
	id      int64
	digest  string
	repo    string
	deleted bool
}

type reportKey struct{ artifact, scanner string }

type runner struct {
	t        *testing.T
	dir      string
	sc       *Scenario
	prefix   string
	scanners map[string]*scanner.Registration
	order    []string        // scanner labels in registration order
	gone     map[string]bool // scanners a delete_scanner step removed
	arts     map[string]*artifactRow
	artOrder []string
	reports  map[reportKey]string
	// cleanupSeen is set by the first cleanup step, cleanupRan once one ran a real cleanupFunc.
	// Unlinked records are recorded only before cleanupSeen, so the golden files do not depend
	// on whether a cleanup exists.
	cleanupSeen bool
	cleanupRan  bool
	lastRows    map[string]string
	mu          sync.Mutex
	res         *Result
}

func newRunner(t *testing.T, dir string, sc *Scenario) *runner {
	return &runner{
		t:        t,
		dir:      dir,
		sc:       sc,
		prefix:   sc.Name + "-" + uuid.NewString()[:8],
		scanners: map[string]*scanner.Registration{},
		gone:     map[string]bool{},
		arts:     map[string]*artifactRow{},
		reports:  map[reportKey]string{},
		res:      &Result{Scenario: sc.Name},
	}
}

func (r *runner) run(ctx context.Context) error {
	defer r.teardown(ctx)
	for _, st := range r.sc.Steps {
		if err := r.step(ctx, st); err != nil {
			return fmt.Errorf("step %s %s/%s: %w", st.Op, st.Artifact, st.Scanner, err)
		}
	}
	return nil
}

func (r *runner) step(ctx context.Context, st Step) error {
	switch st.Op {
	case "register_scanner":
		reg := &scanner.Registration{
			UUID:        uuid.NewString(),
			Name:        r.prefix + "-" + st.Scanner,
			Description: "scan drift scenario scanner",
			URL:         fmt.Sprintf("https://%s.%s.drift.example.com", st.Scanner, r.prefix),
		}
		if _, err := scanner.AddRegistration(ctx, reg); err != nil {
			return err
		}
		r.scanners[st.Scanner] = reg
		r.order = append(r.order, st.Scanner)
		r.record(st, "ok")
	case "scan":
		rpUUID, digest, err := r.prepareScan(ctx, st)
		if err != nil {
			return err
		}
		r.record(st, outcome(r.scan(ctx, st, rpUUID, digest)))
	case "concurrent":
		return r.concurrent(ctx, st.Steps)
	case "delete_artifact":
		a := r.arts[st.Artifact]
		if a == nil || a.deleted {
			return fmt.Errorf("unknown artifact %s", st.Artifact)
		}
		// The artifact delete event handler removes the reports of a digest no other artifact
		// references, then the artifact row goes.
		if err := report.Mgr.DeleteByDigests(ctx, a.digest); err != nil {
			return err
		}
		if err := r.exec(ctx, `DELETE FROM artifact WHERE id = ?`, a.id); err != nil {
			return err
		}
		a.deleted = true
		for k := range r.reports {
			if k.artifact == st.Artifact {
				delete(r.reports, k)
			}
		}
		r.record(st, "ok")
	case "delete_scanner":
		reg := r.scanners[st.Scanner]
		if reg == nil {
			return fmt.Errorf("unknown scanner %s", st.Scanner)
		}
		if err := scanner.DeleteRegistration(ctx, reg.UUID); err != nil {
			return err
		}
		r.gone[st.Scanner] = true
		r.record(st, "ok")
	case "cleanup":
		r.cleanupSeen = true
		if cleanupFunc != nil {
			if err := cleanupFunc(ctx); err != nil {
				return err
			}
			r.cleanupRan = true
		}
		r.record(st, "ok")
	case "capture":
		c, err := r.capture(ctx, st)
		if err != nil {
			return err
		}
		r.res.Captures = append(r.res.Captures, c)
	default:
		return fmt.Errorf("unknown op %q", st.Op)
	}
	return nil
}

// prepareScan creates the artifact and the report placeholder outside the scan itself, the way
// the scan controller does before the job runs. The placeholder is reused on every rescan.
func (r *runner) prepareScan(ctx context.Context, st Step) (string, string, error) {
	reg := r.scanners[st.Scanner]
	if reg == nil {
		return "", "", fmt.Errorf("unknown scanner %s", st.Scanner)
	}
	a, err := r.artifact(ctx, st.Artifact)
	if err != nil {
		return "", "", err
	}
	k := reportKey{st.Artifact, st.Scanner}
	if id, ok := r.reports[k]; ok {
		return id, a.digest, nil
	}
	id, err := report.Mgr.Create(ctx, &scan.Report{
		Digest:           a.digest,
		RegistrationUUID: reg.UUID,
		MimeType:         v1.MimeTypeNativeReport,
	})
	if err != nil {
		return "", "", err
	}
	r.reports[k] = id
	return id, a.digest, nil
}

// scan does what the scan job does after it fetched the report: convert, then store the summary.
func (r *runner) scan(ctx context.Context, st Step, rpUUID, digest string) error {
	raw, err := reportJSON(r.dir, st)
	if err != nil {
		r.t.Errorf("scenario %s: %v", r.sc.Name, err)
		return err
	}
	reg := r.scanners[st.Scanner]
	_, summary, err := postprocessors.Converter.ToRelationalSchema(ctx, rpUUID, reg.UUID, digest, raw)
	if err != nil {
		return err
	}
	return report.Mgr.UpdateReportData(ctx, rpUUID, summary)
}

func (r *runner) concurrent(ctx context.Context, steps []Step) error {
	type prepared struct{ rpUUID, digest string }
	prep := make([]prepared, len(steps))
	for i, st := range steps {
		switch st.Op {
		case "scan":
			id, d, err := r.prepareScan(ctx, st)
			if err != nil {
				return err
			}
			prep[i] = prepared{id, d}
		case "cleanup":
			r.cleanupSeen = true
		default:
			return fmt.Errorf("op %q cannot run concurrently", st.Op)
		}
	}
	results := make([]string, len(steps))
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i, st := range steps {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Each goroutine gets its own ormer, as separate jobs would.
			c := orm.Context()
			<-start
			var err error
			if st.Op == "scan" {
				err = r.scan(c, st, prep[i].rpUUID, prep[i].digest)
			} else if cleanupFunc != nil {
				err = cleanupFunc(c)
				r.mu.Lock()
				r.cleanupRan = true
				r.mu.Unlock()
			}
			results[i] = outcome(err)
		}()
	}
	close(start)
	wg.Wait()
	for i, st := range steps {
		r.record(st, results[i])
	}
	return nil
}

func (r *runner) artifact(ctx context.Context, label string) (*artifactRow, error) {
	if a, ok := r.arts[label]; ok {
		if a.deleted {
			return nil, fmt.Errorf("artifact %s was deleted", label)
		}
		return a, nil
	}
	sum := sha256.Sum256([]byte(r.prefix + "/" + label))
	a := &artifactRow{
		label:  label,
		digest: "sha256:" + hex.EncodeToString(sum[:]),
		repo:   "library/" + r.prefix + "-" + label,
	}
	o, err := orm.FromContext(ctx)
	if err != nil {
		return nil, err
	}
	err = o.Raw(`INSERT INTO artifact (project_id, repository_id, repository_name, digest, type, media_type, manifest_media_type, artifact_type)
VALUES (1, 0, ?, ?, 'IMAGE', 'application/vnd.oci.image.config.v1+json', 'application/vnd.oci.image.manifest.v1+json', 'application/vnd.oci.image.config.v1+json')
RETURNING id`, a.repo, a.digest).QueryRow(&a.id)
	if err != nil {
		return nil, err
	}
	r.arts[label] = a
	r.artOrder = append(r.artOrder, label)
	return a, nil
}

func (r *runner) record(st Step, result string) {
	r.res.Steps = append(r.res.Steps, StepResult{Op: st.Op, Artifact: st.Artifact, Scanner: st.Scanner, Result: result})
}

func outcome(err error) string {
	if err != nil {
		return "error"
	}
	return "ok"
}

func (r *runner) exec(ctx context.Context, sql string, args ...any) error {
	o, err := orm.FromContext(ctx)
	if err != nil {
		return err
	}
	_, err = o.Raw(sql, args...).Exec()
	return err
}

func (r *runner) teardown(ctx context.Context) {
	for _, l := range r.artOrder {
		a := r.arts[l]
		if !a.deleted {
			if err := report.Mgr.DeleteByDigests(ctx, a.digest); err != nil {
				r.t.Errorf("teardown: delete the reports of %s: %v", l, err)
			}
			if err := r.exec(ctx, `DELETE FROM artifact WHERE id = ?`, a.id); err != nil {
				r.t.Errorf("teardown: delete artifact %s: %v", l, err)
			}
		}
	}
	for _, l := range r.order {
		if r.gone[l] {
			continue
		}
		if err := scanner.DeleteRegistration(ctx, r.scanners[l].UUID); err != nil {
			r.t.Errorf("teardown: delete scanner %s: %v", l, err)
		}
	}
}
