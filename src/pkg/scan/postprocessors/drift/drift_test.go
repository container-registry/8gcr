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

// Package drift pins what users see from stored scan reports: the vulnerabilities API, the scan
// summary, Security Hub, the CVE export and the stored records. Golden files were recorded on the
// implementation before the batched write path, and any later change to that path must reproduce
// them. Run with -update only to record a deliberate change, and review the diff.
package drift

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/goharbor/harbor/src/common/dao"
	"github.com/goharbor/harbor/src/lib/config"
	"github.com/goharbor/harbor/src/lib/orm"
	"github.com/goharbor/harbor/src/pkg/scan/vuln"
)

var update = flag.Bool("update", false, "rewrite the golden files from this run")

const (
	scenarioDir = "testdata/scenarios"
	goldenDir   = "testdata/golden"
)

func TestMain(m *testing.M) {
	flag.Parse()
	config.Init()
	dao.PrepareTestForPostgresSQL()
	os.Exit(m.Run())
}

func TestDrift(t *testing.T) {
	scenarios, err := loadScenarios(scenarioDir)
	require.NoError(t, err)
	require.NotEmpty(t, scenarios)

	for _, sc := range scenarios {
		t.Run(sc.Name, func(t *testing.T) {
			got := runScenario(t, sc)
			golden := filepath.Join(goldenDir, sc.Name+".json")
			if *update {
				require.NoError(t, os.WriteFile(golden, got, 0o644))
				return
			}
			want, err := os.ReadFile(golden)
			require.NoError(t, err, "no golden file, record it with -update on the reference implementation")
			msg := "drift from the recorded behavior"
			// Fixing a known bug changes every observation of the scenario, not only the findings
			// it names, so a fix is never accepted silently: it is re-recorded and the diff reviewed.
			if sc.KnownBug != nil && fixedExpectationsHold(t, sc, got) {
				msg = "the known bug no longer reproduces (" + sc.KnownBug.Description + "); review the diff and re-record with -update"
			}
			require.Equal(t, string(want), string(got), msg)
		})
	}
}

// runScenario runs a scenario twice and requires both runs to agree, which proves the
// normalization leaves nothing run-specific in the golden file.
func runScenario(t *testing.T, sc *Scenario) []byte {
	var out [2][]byte
	for i := range out {
		r := newRunner(t, filepath.Dir(scenarioDir), sc)
		require.NoError(t, r.run(orm.Context()))
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		require.NoError(t, enc.Encode(r.res))
		out[i] = buf.Bytes()
	}
	require.Equal(t, string(out[0]), string(out[1]), "two runs of %s disagree", sc.Name)
	return out[1]
}

func fixedExpectationsHold(t *testing.T, sc *Scenario, got []byte) bool {
	var res struct {
		Captures []struct {
			Label   string `json:"label"`
			Reports []struct {
				Artifact string       `json:"artifact"`
				Scanner  string       `json:"scanner"`
				Report   *vuln.Report `json:"report"`
			} `json:"reports"`
		} `json:"captures"`
	}
	require.NoError(t, json.Unmarshal(got, &res))
	for _, exp := range sc.KnownBug.ExpectFixed {
		found := false
		for _, c := range res.Captures {
			if c.Label != exp.Capture {
				continue
			}
			for _, rp := range c.Reports {
				if rp.Artifact != exp.Artifact || rp.Scanner != exp.Scanner {
					continue
				}
				found = true
				var have []KeyTuple
				if rp.Report != nil {
					for _, v := range rp.Report.Vulnerabilities {
						have = append(have, KeyTuple{CVE: v.ID, Package: v.Package, Version: v.Version})
					}
				}
				if fmt.Sprint(sortedTuples(have)) != fmt.Sprint(sortedTuples(exp.Findings)) {
					t.Logf("fixed expectation %s %s@%s: want %v, have %v", exp.Capture, exp.Artifact, exp.Scanner, exp.Findings, have)
					return false
				}
			}
		}
		if !found {
			t.Logf("fixed expectation %s %s@%s: no such report", exp.Capture, exp.Artifact, exp.Scanner)
			return false
		}
	}
	return true
}

func sortedTuples(in []KeyTuple) []KeyTuple {
	out := append([]KeyTuple(nil), in...)
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if fmt.Sprint(out[j]) < fmt.Sprint(out[i]) {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}
