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
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	beegoorm "github.com/beego/beego/v2/client/orm"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/goharbor/harbor/src/lib/orm"
	"github.com/goharbor/harbor/src/lib/q"
	"github.com/goharbor/harbor/src/pkg/scan/dao/scan"
	"github.com/goharbor/harbor/src/pkg/scan/postprocessors"
	"github.com/goharbor/harbor/src/pkg/scan/report"
	v1 "github.com/goharbor/harbor/src/pkg/scan/rest/v1"
	"github.com/goharbor/harbor/src/pkg/scan/vuln"
)

const (
	largeReportSize = 8000   // the report size from the jobservice OOM reports
	largePreload    = 200000 // records of other packages sharing the report's CVE ids
	preloadDigest   = "sha256:00000000000000000000000000000000000000000000000000000000000000d1"
)

// TestDriftLarge is scenario s19: an 8k CVE report against a table that already holds 200k
// records with the same CVE ids. It pins the result by hash and writes the cost of each phase to
// testdata/baseline/s19-<DRIFT_BASELINE_NAME>.json for comparison between implementations.
func TestDriftLarge(t *testing.T) {
	if os.Getenv("DRIFT_LARGE") != "1" {
		t.Skip("set DRIFT_LARGE=1 to run the 8k CVE scenario")
	}
	ctx := orm.Context()
	sc := &Scenario{Name: "s19-large-report"}
	r := newRunner(t, "testdata", sc)
	defer r.teardown(ctx)
	defer func() { _ = report.Mgr.DeleteByDigests(ctx, preloadDigest) }()

	require.NoError(t, r.step(ctx, Step{Op: "register_scanner", Scanner: "s1"}))
	reg := r.scanners["s1"]
	require.NoError(t, preload(ctx, reg.UUID))

	rpUUID, digest, err := r.prepareScan(ctx, Step{Op: "scan", Artifact: "a1", Scanner: "s1"})
	require.NoError(t, err)

	statsOK := resetStatements(ctx)
	baseline := map[string]any{
		"report_vulnerabilities": largeReportSize,
		"preloaded_records":      largePreload,
		"recorded_at":            time.Now().UTC().Format(time.RFC3339),
		"go":                     runtime.Version(),
	}
	phases := []struct {
		name   string
		report string
	}{
		{"first-scan", largeReport(0)},
		{"identical-rescan", largeReport(0)},
		{"rescan-10pct-severity-change", largeReport(10)},
	}
	golden := map[string]any{"scenario": sc.Name}
	for _, p := range phases {
		var convErr error
		start := time.Now()
		heap := peakLiveHeap(func() {
			_, summary, err := postprocessors.Converter.ToRelationalSchema(ctx, rpUUID, reg.UUID, digest, p.report)
			if err == nil {
				err = report.Mgr.UpdateReportData(ctx, rpUUID, summary)
			}
			convErr = err
		})
		elapsed := time.Since(start)
		require.NoError(t, convErr, p.name)

		m := map[string]any{
			"wall_ms":         elapsed.Milliseconds(),
			"peak_heap_bytes": heap,
			"raw_report_size": len(p.report),
		}
		if statsOK {
			m["statements"] = statementStats(ctx)
			resetStatements(ctx)
		}
		baseline[p.name] = m

		obs, err := largeObservation(ctx, r, rpUUID, digest, reg.UUID)
		require.NoError(t, err)
		golden[p.name] = obs
	}
	baseline["explain_current_lookup"] = explainLookup(ctx, reg.UUID)

	writeJSON(t, filepath.Join("testdata", "baseline", "s19-"+baselineName()+".json"), baseline)
	got := encode(t, golden)
	path := filepath.Join(goldenDir, sc.Name+".json")
	if *update {
		require.NoError(t, os.WriteFile(path, got, 0o644))
		return
	}
	want, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, string(want), string(got), "drift from the recorded behavior")
}

func baselineName() string {
	if n := os.Getenv("DRIFT_BASELINE_NAME"); n != "" {
		return n
	}
	return "current"
}

// largeReport mirrors syntheticReport in the postprocessors memory test, with every changeEvery-th
// item raised to Critical when changeEvery > 0.
func largeReport(changeEvery int) string {
	const description = "A flaw was found in the way the package handles untrusted input. " +
		"An attacker able to reach the affected code path can cause a crash or, depending on the " +
		"allocator, achieve memory corruption. This entry exists to give the synthetic report the " +
		"same per-item weight a real scanner report has."
	items := make([]*vuln.VulnerabilityItem, 0, largeReportSize)
	for i := range largeReportSize {
		score := 7.5
		sev := vuln.High
		if changeEvery > 0 && i%changeEvery == 0 {
			sev = vuln.Critical
		}
		items = append(items, &vuln.VulnerabilityItem{
			ID:          fmt.Sprintf("CVE-2026-%06d", i),
			Package:     fmt.Sprintf("package-%d", i%512),
			Version:     "1.2.3-4",
			FixVersion:  "1.2.4-1",
			Severity:    sev,
			Description: description,
			Links: []string{
				fmt.Sprintf("https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-%06d", i),
				fmt.Sprintf("https://security-tracker.example.org/tracker/CVE-2026-%06d", i),
			},
			CWEIds:      []string{"CWE-787", "CWE-125"},
			CVSSDetails: vuln.CVSS{ScoreV3: &score, VectorV3: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		})
	}
	data, err := json.Marshal(&vuln.Report{GeneratedAt: "2026-11-25T00:00:00Z", Severity: vuln.High, Vulnerabilities: items})
	if err != nil {
		panic(err)
	}
	return string(data)
}

// preload fills the table the way a busy registry does: every CVE id of the report is already
// stored for 25 other packages, all linked to another artifact's report.
func preload(ctx context.Context, scannerUUID string) error {
	o, err := orm.FromContext(ctx)
	if err != nil {
		return err
	}
	other := &scan.Report{
		UUID:             uuid.NewString(),
		Digest:           preloadDigest,
		RegistrationUUID: scannerUUID,
		MimeType:         v1.MimeTypeNativeReport,
	}
	if _, err := scan.New().Create(ctx, other); err != nil {
		return err
	}
	stmts := []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO vulnerability_record (cve_id, registration_uuid, package, package_version, package_type, severity, fixed_version, urls, description, cvss_score_v3)
SELECT format('CVE-2026-%s', lpad((g % ?)::text, 6, '0')), ?, 'other-' || (g / ?), '9.9', 'Unknown', 'High', '10.0',
       'https://cve.mitre.org/x|https://security-tracker.example.org/y', repeat('preloaded description ', 15), 7.5
FROM generate_series(0, ? - 1) g`, []any{largeReportSize, scannerUUID, largeReportSize, largePreload}},
		{`INSERT INTO report_vulnerability_record (report_uuid, vuln_record_id)
SELECT ?, id FROM vulnerability_record WHERE registration_uuid = ?`, []any{other.UUID, scannerUUID}},
		{`ANALYZE vulnerability_record`, nil},
		{`ANALYZE report_vulnerability_record`, nil},
	}
	for _, s := range stmts {
		if _, err := o.Raw(s.sql, s.args...).Exec(); err != nil {
			return err
		}
	}
	return nil
}

// largeObservation pins the result by hash: the full report is too large for a golden file.
func largeObservation(ctx context.Context, r *runner, rpUUID, digest, scannerUUID string) (any, error) {
	rps, err := report.Mgr.List(ctx, q.New(q.KeyWords{"uuid": rpUUID}))
	if err != nil || len(rps) != 1 {
		return nil, fmt.Errorf("report %s: %v", rpUUID, err)
	}
	complete, err := postprocessors.Converter.FromRelationalSchema(ctx, rpUUID, digest, rps[0].Report)
	if err != nil {
		return nil, err
	}
	rep := r.normalizeReport(complete).(map[string]any)
	items, _ := rep["vulnerabilities"].([]any)
	data, _ := json.Marshal(rep)
	sum := sha256.Sum256(data)

	o, err := orm.FromContext(ctx)
	if err != nil {
		return nil, err
	}
	var total, unlinked int64
	if err := o.Raw(`SELECT count(*) FROM vulnerability_record WHERE registration_uuid = ?`, scannerUUID).QueryRow(&total); err != nil {
		return nil, err
	}
	if err := o.Raw(`SELECT count(*) FROM vulnerability_record v WHERE registration_uuid = ?
AND NOT EXISTS (SELECT 1 FROM report_vulnerability_record r WHERE r.vuln_record_id = v.id)`, scannerUUID).QueryRow(&unlinked); err != nil {
		return nil, err
	}
	return map[string]any{
		"report_items":     len(items),
		"report_sha256":    hex.EncodeToString(sum[:]),
		"critical_cnt":     rps[0].CriticalCnt,
		"high_cnt":         rps[0].HighCnt,
		"fixable_cnt":      rps[0].FixableCnt,
		"records_total":    total,
		"records_unlinked": unlinked,
	}, nil
}

// resetStatements clears pg_stat_statements, reporting false where the extension is not loaded
// (CI starts Postgres without shared_preload_libraries).
func resetStatements(ctx context.Context) bool {
	o, err := orm.FromContext(ctx)
	if err != nil {
		return false
	}
	if _, err := o.Raw(`CREATE EXTENSION IF NOT EXISTS pg_stat_statements`).Exec(); err != nil {
		return false
	}
	_, err = o.Raw(`SELECT pg_stat_statements_reset()`).Exec()
	return err == nil
}

func statementStats(ctx context.Context) any {
	o, err := orm.FromContext(ctx)
	if err != nil {
		return err.Error()
	}
	var totals []beegoorm.Params
	_, err = o.Raw(`SELECT sum(calls)::text AS calls, sum(rows)::text AS rows, round(sum(total_exec_time)::numeric, 1)::text AS exec_ms
FROM pg_stat_statements WHERE dbid = (SELECT oid FROM pg_database WHERE datname = current_database())
AND query NOT ILIKE '%pg_stat_statements%'`).Values(&totals)
	if err != nil {
		return err.Error()
	}
	var top []beegoorm.Params
	_, err = o.Raw(`SELECT calls::text AS calls, rows::text AS rows, round(total_exec_time::numeric, 1)::text AS exec_ms,
       round(shared_blks_hit + shared_blks_read)::text AS blocks, left(regexp_replace(query, '\s+', ' ', 'g'), 160) AS query
FROM pg_stat_statements WHERE dbid = (SELECT oid FROM pg_database WHERE datname = current_database())
AND query NOT ILIKE '%pg_stat_statements%' ORDER BY total_exec_time DESC LIMIT 8`).Values(&top)
	if err != nil {
		return err.Error()
	}
	return map[string]any{"total": totals, "top": top}
}

// explainLookup plans the lookup the current toSchema sends: every CVE id of the report and the
// scanner, nothing else.
func explainLookup(ctx context.Context, scannerUUID string) any {
	o, err := orm.FromContext(ctx)
	if err != nil {
		return err.Error()
	}
	ids := make([]string, largeReportSize)
	for i := range ids {
		ids[i] = fmt.Sprintf("'CVE-2026-%06d'", i)
	}
	var plan []beegoorm.Params
	sql := fmt.Sprintf(`EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT) SELECT * FROM vulnerability_record WHERE cve_id IN (%s) AND registration_uuid = ?`, strings.Join(ids, ","))
	if _, err := o.Raw(sql, scannerUUID).Values(&plan); err != nil {
		return err.Error()
	}
	lines := make([]string, 0, len(plan))
	for _, p := range plan {
		line := fmt.Sprint(p["QUERY PLAN"])
		if len(line) > 200 { // the filter line repeats all 8000 ids
			line = line[:200] + "..."
		}
		lines = append(lines, line)
	}
	return lines
}

func peakLiveHeap(fn func()) uint64 {
	restore := debug.SetGCPercent(1)
	defer debug.SetGCPercent(restore)
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	base := ms.HeapAlloc

	var peak atomic.Uint64
	done := make(chan struct{})
	ready := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		var s runtime.MemStats
		first := true
		for {
			select {
			case <-done:
				return
			default:
			}
			// ReadMemStats stops the world; sampling every millisecond keeps it from dominating
			// a run that spends most of its time waiting on the database.
			runtime.ReadMemStats(&s)
			time.Sleep(time.Millisecond)
			for {
				seen := peak.Load()
				if s.HeapAlloc <= seen || peak.CompareAndSwap(seen, s.HeapAlloc) {
					break
				}
			}
			if first {
				first = false
				close(ready)
			}
		}
	}()
	<-ready
	fn()
	close(done)
	wg.Wait()
	if peak.Load() < base {
		return 0
	}
	return peak.Load() - base
}

func encode(t *testing.T, v any) []byte {
	var sb strings.Builder
	enc := json.NewEncoder(&sb)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	require.NoError(t, enc.Encode(v))
	return []byte(sb.String())
}

func writeJSON(t *testing.T, path string, v any) {
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, encode(t, v), 0o644))
}
