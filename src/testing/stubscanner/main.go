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

// Command stubscanner is a pluggable scanner adapter that returns canned reports, so a Harbor
// instance can be driven through recorded scan scenarios (tests/scan-drift).
//
// The test driver stores the report for an artifact with PUT /stub/reports?key=<repository>:<tag>.
// A scan request snapshots the report stored for its artifact, and the report endpoint returns that
// snapshot verbatim, including an empty body. Any path prefix is accepted, so several scanner
// registrations can point at one process: http://host:port/s1, http://host:port/s2.
package main

import (
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"

	"github.com/google/uuid"

	v1 "github.com/goharbor/harbor/src/pkg/scan/rest/v1"
)

type store struct {
	mu      sync.Mutex
	reports map[string]string // artifact key -> report body
	scans   map[string]string // scan id -> report body at scan time
}

func main() {
	addr := flag.String("addr", ":8089", "listen address")
	flag.Parse()
	s := &store{reports: map[string]string{}, scans: map[string]string{}}
	log.Printf("stub scanner listening on %s", *addr)
	log.Fatal(http.ListenAndServe(*addr, s))
}

func (s *store) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	switch {
	case r.Method == http.MethodPut && strings.HasSuffix(p, "/stub/reports"):
		s.putReport(w, r)
	case r.Method == http.MethodGet && strings.HasSuffix(p, "/api/v1/metadata"):
		s.metadata(w, p)
	case r.Method == http.MethodPost && strings.HasSuffix(p, "/api/v1/scan"):
		s.scan(w, r)
	case r.Method == http.MethodGet && strings.HasSuffix(p, "/report") && strings.Contains(p, "/api/v1/scan/"):
		s.report(w, p)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func (s *store) putReport(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	body, err := io.ReadAll(r.Body)
	if err != nil || key == "" {
		http.Error(w, "key query parameter and body required", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.reports[key] = string(body)
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (s *store) metadata(w http.ResponseWriter, path string) {
	// The prefix names the registration, so each one reports its own scanner name.
	name := strings.Trim(strings.TrimSuffix(path, "/api/v1/metadata"), "/")
	if name == "" {
		name = "stub"
	}
	md := &v1.ScannerAdapterMetadata{
		Scanner: &v1.Scanner{Name: "Stub-" + name, Vendor: "scan-drift", Version: "1.0"},
		Capabilities: []*v1.ScannerCapability{{
			Type:              v1.ScanTypeVulnerability,
			ConsumesMimeTypes: []string{v1.MimeTypeOCIArtifact, v1.MimeTypeDockerArtifact},
			ProducesMimeTypes: []string{v1.MimeTypeNativeReport},
		}},
		Properties: v1.ScannerProperties{"harbor.scanner-adapter/scanner-type": "os-package-vulnerability"},
	}
	w.Header().Set("Content-Type", v1.MimeTypeAdapterMeta)
	_ = json.NewEncoder(w).Encode(md)
}

func (s *store) scan(w http.ResponseWriter, r *http.Request) {
	req := &v1.ScanRequest{}
	if err := json.NewDecoder(r.Body).Decode(req); err != nil || req.Artifact == nil {
		http.Error(w, "invalid scan request", http.StatusBadRequest)
		return
	}
	key := req.Artifact.Repository + ":" + req.Artifact.Tag
	// The key comes from the request; without line breaks it cannot forge log lines.
	logKey := strings.NewReplacer("\n", "", "\r", "").Replace(key)
	s.mu.Lock()
	body, ok := s.reports[key]
	if !ok {
		s.mu.Unlock()
		log.Printf("scan for %s: no report stored", logKey)
		http.Error(w, "no report stored for "+key, http.StatusBadRequest)
		return
	}
	id := uuid.NewString()
	s.scans[id] = body
	s.mu.Unlock()
	log.Printf("scan %s for %s (%d bytes)", id, logKey, len(body))
	w.Header().Set("Content-Type", v1.MimeTypeScanResponse)
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(&v1.ScanResponse{ID: id})
}

func (s *store) report(w http.ResponseWriter, path string) {
	id := path[strings.Index(path, "/api/v1/scan/")+len("/api/v1/scan/"):]
	id = strings.TrimSuffix(id, "/report")
	s.mu.Lock()
	body, ok := s.scans[id]
	s.mu.Unlock()
	if !ok {
		http.Error(w, "unknown scan "+id, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", v1.MimeTypeNativeReport)
	_, _ = io.WriteString(w, body)
}
