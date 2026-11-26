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
	"encoding/json"
	"fmt"
	"maps"
	"sort"
	"strconv"

	beegoorm "github.com/beego/beego/v2/client/orm"

	"github.com/goharbor/harbor/src/jobservice/job"
	"github.com/goharbor/harbor/src/lib/orm"
	"github.com/goharbor/harbor/src/lib/q"
	"github.com/goharbor/harbor/src/pkg/scan/export"
	"github.com/goharbor/harbor/src/pkg/scan/postprocessors"
	"github.com/goharbor/harbor/src/pkg/scan/report"
	shdao "github.com/goharbor/harbor/src/pkg/securityhub/dao"
)

// Result is what a golden file holds for one scenario.
type Result struct {
	Scenario string       `json:"scenario"`
	Steps    []StepResult `json:"steps"`
	Captures []Capture    `json:"captures"`
}

// StepResult records only ok or error: error texts are free to change, outcomes are not.
type StepResult struct {
	Op       string `json:"op"`
	Artifact string `json:"artifact,omitempty"`
	Scanner  string `json:"scanner,omitempty"`
	Result   string `json:"result"`
}

// Capture holds the observations O1-O5 at one point of a scenario.
type Capture struct {
	Label string `json:"label"`
	// RowsUnchanged is set when the capture asked whether anything was written since the
	// previous capture.
	RowsUnchanged *bool `json:"rows_unchanged,omitempty"`
	// O1 and O2, per artifact and scanner.
	Reports []any `json:"reports"`
	// O3, per scanner still registered.
	SecurityHub []any `json:"security_hub"`
	// O4, for every live artifact.
	Export []any `json:"export"`
	// O5, per scanner ever registered.
	Records []any `json:"records"`
}

// The Security Hub dashboard queries cut their result at five rows, ordered by values that can
// tie. Which tied row makes the cut depends on physical row order, so a cut list is recorded by
// its ordering values only.
const securityHubLimit = 5

func (r *runner) capture(ctx context.Context, st Step) (Capture, error) {
	c := Capture{Label: st.Label}
	if st.RowsUnchanged {
		rows, err := r.rowVersions(ctx)
		if err != nil {
			return c, err
		}
		same := r.lastRows != nil && maps.Equal(rows, r.lastRows)
		c.RowsUnchanged = &same
	}
	// Every capture refreshes the snapshot, so rows_unchanged compares against the capture
	// right before it.
	rows, err := r.rowVersions(ctx)
	if err != nil {
		return c, err
	}
	r.lastRows = rows

	for _, k := range r.reportKeys() {
		obs, err := r.observeReport(ctx, k)
		if err != nil {
			return c, fmt.Errorf("report %s@%s: %w", k.artifact, k.scanner, err)
		}
		c.Reports = append(c.Reports, obs)
	}
	for _, l := range r.order {
		obs, err := r.observeSecurityHub(ctx, l)
		if err != nil {
			return c, fmt.Errorf("security hub %s: %w", l, err)
		}
		if obs != nil {
			c.SecurityHub = append(c.SecurityHub, obs)
		}
	}
	if c.Export, err = r.observeExport(ctx); err != nil {
		return c, fmt.Errorf("export: %w", err)
	}
	for _, l := range r.order {
		obs, err := r.observeRecords(ctx, l)
		if err != nil {
			return c, fmt.Errorf("records %s: %w", l, err)
		}
		c.Records = append(c.Records, obs)
	}
	return c, nil
}

func (r *runner) reportKeys() []reportKey {
	keys := make([]reportKey, 0, len(r.reports))
	for k := range r.reports {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].artifact != keys[j].artifact {
			return keys[i].artifact < keys[j].artifact
		}
		return keys[i].scanner < keys[j].scanner
	})
	return keys
}

// observeReport is O1 (the report the vulnerabilities API, the pull block and the allowlist see)
// and O2 (the summary behind the scan overview and the webhook, plus the stored counters).
func (r *runner) observeReport(ctx context.Context, k reportKey) (any, error) {
	rpUUID := r.reports[k]
	rps, err := report.Mgr.List(ctx, q.New(q.KeyWords{"uuid": rpUUID}))
	if err != nil {
		return nil, err
	}
	if len(rps) != 1 {
		return nil, fmt.Errorf("want 1 report for %s, got %d", rpUUID, len(rps))
	}
	rp := rps[0]
	a := r.arts[k.artifact]
	complete, err := postprocessors.Converter.FromRelationalSchema(ctx, rp.UUID, a.digest, rp.Report)
	if err != nil {
		return nil, err
	}

	obs := map[string]any{
		"artifact": k.artifact,
		"scanner":  k.scanner,
		"counts": map[string]int64{
			"critical": rp.CriticalCnt, "high": rp.HighCnt, "medium": rp.MediumCnt, "low": rp.LowCnt,
			"none": rp.NoneCnt, "unknown": rp.UnknownCnt, "fixable": rp.FixableCnt,
		},
		"stored_report": r.parseJSON(rp.Report),
		"report":        r.normalizeReport(complete),
	}

	full := *rp
	full.Report = complete
	full.Status = job.SuccessStatus.String()
	sum, err := report.GenerateSummary(&full)
	if err != nil {
		obs["summary"] = map[string]any{"error": true}
	} else {
		s := r.normalize(sum).(map[string]any)
		for _, f := range []string{"report_id", "start_time", "end_time", "duration"} {
			delete(s, f)
		}
		obs["summary"] = s
	}
	return obs, nil
}

// normalizeReport sorts the findings. Their order is not compared: GetForReport has no ORDER BY,
// and the order already varies between runs of the same implementation with the query plan.
func (r *runner) normalizeReport(data string) any {
	if data == "" {
		return nil
	}
	v, ok := r.parseJSON(data).(map[string]any)
	if !ok {
		return v
	}
	if items, ok := v["vulnerabilities"].([]any); ok {
		sortByJSON(items, "id", "package", "version")
	}
	return v
}

// observeSecurityHub is O3: the Security Hub summary, dashboard lists and the vulnerability list.
func (r *runner) observeSecurityHub(ctx context.Context, label string) (any, error) {
	reg := r.scanners[label]
	if ok, err := r.scannerExists(ctx, reg.UUID); err != nil || !ok {
		return nil, err
	}
	hub := shdao.New()
	obs := map[string]any{"scanner": label}

	sum, err := hub.Summary(ctx, reg.UUID, 0, nil)
	if err != nil {
		return nil, err
	}
	obs["summary"] = r.normalize(sum)
	scanned, err := hub.ScannedArtifactsCount(ctx, reg.UUID, 0, nil)
	if err != nil {
		return nil, err
	}
	obs["scanned_artifacts"] = scanned

	arts, err := hub.DangerousArtifacts(ctx, reg.UUID, 0, nil)
	if err != nil {
		return nil, err
	}
	obs["dangerous_artifacts"] = r.topList(arts, "repository", "digest", "project")

	cves, err := hub.DangerousCVEs(ctx, reg.UUID, 0, nil)
	if err != nil {
		return nil, err
	}
	obs["dangerous_cves"] = r.topList(cves, "ID")

	filters := []struct {
		name string
		kw   q.KeyWords
	}{
		{"all", nil},
		{"critical", q.KeyWords{"severity": "Critical"}},
		{"cvss_7_or_more", q.KeyWords{"cvss_score_v3": &q.Range{Min: 7.0}}},
	}
	lists := map[string]any{}
	for _, f := range filters {
		query := &q.Query{Keywords: f.kw, PageNumber: 1, PageSize: 100000}
		items, err := hub.ListVulnerabilities(ctx, reg.UUID, 0, query)
		if err != nil {
			return nil, err
		}
		cnt, err := hub.CountVulnerabilities(ctx, reg.UUID, 0, false, &q.Query{Keywords: f.kw})
		if err != nil {
			return nil, err
		}
		rows := r.normalize(items).([]any)
		for _, row := range rows {
			m := row.(map[string]any)
			delete(m, "ID")
			delete(m, "ProjectID")
			m["ArtifactID"] = r.artifactLabelByID(m["ArtifactID"])
		}
		sortByJSON(rows)
		lists[f.name] = map[string]any{"count": cnt, "items": rows}
	}
	obs["vulnerabilities"] = lists
	return obs, nil
}

// topList records a dashboard top-5 list. A full list keeps only the ordering values, see
// securityHubLimit.
func (r *runner) topList(v any, drop ...string) any {
	rows, _ := r.normalize(v).([]any)
	for _, row := range rows {
		m := row.(map[string]any)
		for _, d := range drop {
			delete(m, d)
		}
	}
	if len(rows) < securityHubLimit {
		sortByJSON(rows)
		return map[string]any{"complete": true, "rows": rows}
	}
	keep := []string{"critical_cnt", "high_cnt", "medium_cnt", "low_cnt", "CVE3Score", "Severity"}
	out := make([]any, 0, len(rows))
	for _, row := range rows {
		m := row.(map[string]any)
		o := map[string]any{}
		for _, k := range keep {
			if val, ok := m[k]; ok {
				o[k] = val
			}
		}
		out = append(out, o)
	}
	sortByJSON(out)
	return map[string]any{"complete": false, "ordering_values": out}
}

// observeExport is O4: the rows of the CVE CSV export.
func (r *runner) observeExport(ctx context.Context) ([]any, error) {
	var ids []int64
	for _, l := range r.artOrder {
		if a := r.arts[l]; !a.deleted {
			ids = append(ids, a.id)
		}
	}
	if len(ids) == 0 {
		return []any{}, nil
	}
	data, err := export.NewManager().Fetch(ctx, export.Params{ArtifactIDs: ids, PageNumber: 1, PageSize: 100000})
	if err != nil {
		return nil, err
	}
	rows, _ := r.normalize(data).([]any)
	if rows == nil {
		rows = []any{}
	}
	sortByJSON(rows)
	return rows, nil
}

// observeRecords is O5: what is stored per scanner, compared by key tuple, never by id.
func (r *runner) observeRecords(ctx context.Context, label string) (any, error) {
	reg := r.scanners[label]
	o, err := orm.FromContext(ctx)
	if err != nil {
		return nil, err
	}
	var recs []beegoorm.Params
	_, err = o.Raw(`SELECT cve_id, package, package_version, package_type, severity, status, fixed_version, urls,
       cvss_score_v3::text AS cvss_score_v3, cvss_score_v2::text AS cvss_score_v2, cvss_vector_v3, cvss_vector_v2,
       description, cwe_ids, vendor_attributes::text AS vendor_attributes,
       EXISTS (SELECT 1 FROM report_vulnerability_record r WHERE r.vuln_record_id = v.id)::text AS linked
FROM vulnerability_record v WHERE registration_uuid = ?`, reg.UUID).Values(&recs)
	if err != nil {
		return nil, err
	}
	linked, unlinked := []any{}, []any{}
	for _, rec := range recs {
		m := map[string]any{}
		for k, v := range rec {
			m[k] = v
		}
		isLinked := m["linked"] == "true"
		delete(m, "linked")
		if isLinked {
			linked = append(linked, r.normalize(m))
		} else {
			unlinked = append(unlinked, r.normalize(m))
		}
	}
	sortByJSON(linked, "cve_id", "package", "package_version")
	sortByJSON(unlinked, "cve_id", "package", "package_version")

	var links []beegoorm.Params
	_, err = o.Raw(`SELECT r.report_uuid, v.cve_id, v.package, v.package_version
FROM report_vulnerability_record r JOIN vulnerability_record v ON v.id = r.vuln_record_id
WHERE v.registration_uuid = ?`, reg.UUID).Values(&links)
	if err != nil {
		return nil, err
	}
	perReport := map[string][]any{}
	for _, l := range links {
		rl := r.reportLabel(fmt.Sprint(l["report_uuid"]))
		perReport[rl] = append(perReport[rl], []any{l["cve_id"], l["package"], l["package_version"]})
	}
	for _, v := range perReport {
		sortByJSON(v)
	}
	obs := map[string]any{
		"scanner":        label,
		"linked_records": linked,
		"links":          perReport,
	}
	if r.cleanupSeen {
		// With a cleanup in place nothing may stay unlinked. Without one the count is whatever
		// the scenario left behind, which the cleanup is meant to change.
		if r.cleanupRan && len(unlinked) != 0 {
			r.t.Errorf("scenario %s: %d unlinked records survived the cleanup for scanner %s", r.sc.Name, len(unlinked), label)
		}
		obs["unlinked_records"] = "after-cleanup"
	} else {
		obs["unlinked_records"] = unlinked
	}
	return obs, nil
}

// rowVersions maps every record and link row of the scenario to its xmin, which changes on any
// write to the row.
func (r *runner) rowVersions(ctx context.Context) (map[string]string, error) {
	o, err := orm.FromContext(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, l := range r.order {
		var rows []beegoorm.Params
		_, err := o.Raw(`SELECT 'r' || v.id AS k, v.xmin::text AS x FROM vulnerability_record v WHERE v.registration_uuid = ?
UNION ALL
SELECT 'l' || r.id, r.xmin::text FROM report_vulnerability_record r JOIN vulnerability_record v ON v.id = r.vuln_record_id
WHERE v.registration_uuid = ?`, r.scanners[l].UUID, r.scanners[l].UUID).Values(&rows)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			out[fmt.Sprint(row["k"])] = fmt.Sprint(row["x"])
		}
	}
	return out, nil
}

func (r *runner) scannerExists(ctx context.Context, id string) (bool, error) {
	o, err := orm.FromContext(ctx)
	if err != nil {
		return false, err
	}
	var n int64
	err = o.Raw(`SELECT count(*) FROM scanner_registration WHERE uuid = ?`, id).QueryRow(&n)
	return n == 1, err
}

func (r *runner) reportLabel(id string) string {
	for k, v := range r.reports {
		if v == id {
			return k.artifact + "@" + k.scanner
		}
	}
	return "unknown-report"
}

func (r *runner) artifactLabelByID(v any) any {
	id, err := strconv.ParseInt(fmt.Sprint(v), 10, 64)
	if err != nil {
		return v
	}
	for _, a := range r.arts {
		if a.id == id {
			return a.label
		}
	}
	return "unknown-artifact"
}

func (r *runner) parseJSON(s string) any {
	if s == "" {
		return nil
	}
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return map[string]any{"invalid_json": s}
	}
	return r.relabel(v)
}

// normalize turns any value into plain JSON data with run-specific values replaced by labels.
func (r *runner) normalize(v any) any {
	data, err := json.Marshal(v)
	if err != nil {
		r.t.Fatalf("marshal observation: %v", err)
	}
	return r.parseJSON(string(data))
}

// longString is the length above which a string is recorded by its hash, so a large description
// does not bloat the golden files.
const longString = 512

func (r *runner) relabel(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			t[k] = r.relabel(val)
		}
		return t
	case []any:
		for i, val := range t {
			t[i] = r.relabel(val)
		}
		return t
	case string:
		for _, a := range r.arts {
			if t == a.digest {
				return "<digest:" + a.label + ">"
			}
			if t == a.repo {
				return "<repo:" + a.label + ">"
			}
		}
		for l, reg := range r.scanners {
			if t == reg.UUID {
				return "<scanner-uuid:" + l + ">"
			}
			if t == reg.Name {
				return "<scanner-name:" + l + ">"
			}
		}
		for k, id := range r.reports {
			if t == id {
				return "<report:" + k.artifact + "@" + k.scanner + ">"
			}
		}
		if len(t) > longString {
			sum := sha256.Sum256([]byte(t))
			return fmt.Sprintf("<long:%d:%s>", len(t), hex.EncodeToString(sum[:8]))
		}
		return t
	}
	return v
}

// sortByJSON orders rows by the given map keys first, then by their full JSON, which makes the
// order total and independent of database collation and physical row order.
func sortByJSON(rows []any, keys ...string) {
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return string(b)
	}
	sort.SliceStable(rows, func(i, j int) bool {
		mi, iok := rows[i].(map[string]any)
		mj, jok := rows[j].(map[string]any)
		if iok && jok {
			for _, k := range keys {
				a, b := fmt.Sprint(mi[k]), fmt.Sprint(mj[k])
				if a != b {
					return a < b
				}
			}
		}
		return enc(rows[i]) < enc(rows[j])
	})
}
