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

package lib

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/goharbor/harbor/src/lib/log"
)

const (
	cgroupRoot        = "/sys/fs/cgroup"
	procSelfCgroup    = "/proc/self/cgroup"
	cgroupV1MemoryMax = "/sys/fs/cgroup/memory/memory.limit_in_bytes"
	// cgroup v1 reports "no limit" as a page-aligned value near MaxInt64.
	cgroupV1Unlimited = int64(1) << 62
	memLimitRatio     = 0.9
)

// SetMemoryLimitFromCgroup sets the Go soft memory limit to 90% of the
// container memory limit, so the GC runs before the kernel OOM-kills the
// process. An explicit GOMEMLIMIT env always wins.
func SetMemoryLimitFromCgroup() {
	if v := os.Getenv("GOMEMLIMIT"); v != "" {
		log.Infof("GOMEMLIMIT=%s set explicitly, not deriving it from the cgroup limit", v)
		return
	}
	limit, err := cgroupV2MemoryLimit(cgroupRoot, procSelfCgroup)
	if err == nil && limit == 0 {
		limit, err = cgroupMemoryLimit(cgroupV1MemoryMax)
	}
	if err != nil {
		log.Warningf("cannot read the cgroup memory limit, leaving GOMEMLIMIT unset: %v", err)
		return
	}
	if limit <= 0 {
		log.Debug("no cgroup memory limit, leaving GOMEMLIMIT unset")
		return
	}
	soft := int64(float64(limit) * memLimitRatio)
	debug.SetMemoryLimit(soft)
	log.Infof("set Go memory limit to %d bytes (90%% of the %d byte cgroup limit)", soft, limit)
}

// cgroupV2MemoryLimit returns the lowest memory.max from the process's own
// cgroup (per procCgroup) up to root, or 0 when none of them is limited.
func cgroupV2MemoryLimit(root, procCgroup string) (int64, error) {
	rel := "/"
	if b, err := os.ReadFile(procCgroup); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if p, ok := strings.CutPrefix(line, "0::"); ok {
				rel = path.Clean("/" + p)
				break
			}
		}
	}
	var lowest int64
	for {
		limit, err := cgroupMemoryLimit(filepath.Join(root, rel, "memory.max"))
		if err != nil {
			return 0, err
		}
		if limit > 0 && (lowest == 0 || limit < lowest) {
			lowest = limit
		}
		if rel == "/" {
			return lowest, nil
		}
		rel = path.Dir(rel)
	}
}

// cgroupMemoryLimit returns the memory limit in bytes from the first file
// that exists, or 0 when there is no limit or no cgroup file at all.
func cgroupMemoryLimit(paths ...string) (int64, error) {
	for _, p := range paths {
		b, err := os.ReadFile(p) // nolint:gosec // only cgroup files under /sys/fs/cgroup.
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return 0, err
		}
		return parseCgroupMemoryLimit(string(b))
	}
	return 0, nil
}

func parseCgroupMemoryLimit(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "max" {
		return 0, nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse cgroup memory limit %q: %w", s, err)
	}
	if n <= 0 || n >= cgroupV1Unlimited {
		return 0, nil
	}
	return n, nil
}
