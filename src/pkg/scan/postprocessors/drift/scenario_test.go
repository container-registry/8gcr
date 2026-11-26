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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"sigs.k8s.io/yaml"

	"github.com/goharbor/harbor/src/pkg/scan/vuln"
)

// Scenario is one recorded sequence of operations against the scan report persistence path. The
// same files drive the API-level replay in tests/scan-drift, so the format is plain data.
type Scenario struct {
	Name        string    `json:"name"`
	Description string    `json:"description"`
	KnownBug    *KnownBug `json:"known_bug,omitempty"`
	Steps       []Step    `json:"steps"`
}

// KnownBug marks a scenario whose golden file pins a defect on purpose. ExpectFixed is the finding
// set a fixed implementation must produce; when it holds, the drift report says so.
type KnownBug struct {
	Description string             `json:"description"`
	ExpectFixed []FixedExpectation `json:"expect_fixed"`
}

// FixedExpectation is the finding set one report must show once the bug is fixed.
type FixedExpectation struct {
	Capture  string     `json:"capture"`
	Artifact string     `json:"artifact"`
	Scanner  string     `json:"scanner"`
	Findings []KeyTuple `json:"findings"`
}

// KeyTuple identifies a finding without the ambiguous "cve-package-version" string key.
type KeyTuple struct {
	CVE     string `json:"cve"`
	Package string `json:"package"`
	Version string `json:"version"`
}

// Step ops: register_scanner, scan, delete_artifact, delete_scanner, cleanup, capture, concurrent.
type Step struct {
	Op       string `json:"op"`
	Scanner  string `json:"scanner,omitempty"`
	Artifact string `json:"artifact,omitempty"`
	// Exactly one report source for op scan. RawReport is sent verbatim, which is how the
	// empty and null report cases are expressed.
	Report     *vuln.Report `json:"report,omitempty"`
	ReportFile string       `json:"report_file,omitempty"`
	RawReport  *string      `json:"raw_report,omitempty"`
	// Label names a capture.
	Label string `json:"label,omitempty"`
	// RowsUnchanged makes a capture record whether any vulnerability_record or
	// report_vulnerability_record row was written since the previous capture.
	RowsUnchanged bool `json:"rows_unchanged,omitempty"`
	// Steps of a concurrent group run in parallel.
	Steps []Step `json:"steps,omitempty"`
}

func loadScenarios(dir string) ([]*Scenario, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	out := make([]*Scenario, 0, len(files))
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		s := &Scenario{}
		if err := yaml.UnmarshalStrict(data, s); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		if want := strings.TrimSuffix(filepath.Base(f), ".yaml"); s.Name != want {
			return nil, fmt.Errorf("%s: name %q must match the file name", f, s.Name)
		}
		if s.KnownBug != nil && len(s.KnownBug.ExpectFixed) == 0 {
			return nil, fmt.Errorf("%s: known_bug needs at least one expect_fixed entry", f)
		}
		out = append(out, s)
	}
	return out, nil
}

// reportJSON renders the report a scan step hands to the converter.
func reportJSON(dir string, st Step) (string, error) {
	switch {
	case st.RawReport != nil:
		return *st.RawReport, nil
	case st.ReportFile != "":
		data, err := os.ReadFile(filepath.Join(dir, "reports", st.ReportFile))
		return string(data), err
	case st.Report != nil:
		data, err := json.Marshal(st.Report)
		return string(data), err
	}
	return "", fmt.Errorf("scan step for %s/%s has no report", st.Artifact, st.Scanner)
}
