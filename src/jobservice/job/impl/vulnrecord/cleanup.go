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

// Package vulnrecord holds the job that deletes vulnerability records no scan report links to.
package vulnrecord

import (
	"time"

	"github.com/goharbor/harbor/src/jobservice/job"
	"github.com/goharbor/harbor/src/pkg/scan/dao/scan"
)

const (
	// Records looked at per transaction. Report conversions wait for each batch, so a batch stays short.
	batchSize = 5000
	// Pause between batches, leaving room for the conversions that queued behind the last one.
	batchPause = 100 * time.Millisecond
)

// Cleanup deletes the vulnerability records left behind when a rescan, an artifact deletion or a
// report deletion removed the last link to them. Nothing else deletes them, so without this job
// the table only grows.
type Cleanup struct {
	dao scan.VulnerabilityRecordDao
}

// MaxFails implements the job interface.
func (c *Cleanup) MaxFails() uint { return 1 }

// MaxCurrency implements the job interface.
func (c *Cleanup) MaxCurrency() uint { return 1 }

// ShouldRetry implements the job interface. A rerun continues where the failed one stopped,
// because deleted records are gone.
func (c *Cleanup) ShouldRetry() bool { return true }

// Validate implements the job interface.
func (c *Cleanup) Validate(_ job.Parameters) error { return nil }

// Run walks the table in id order, one batch at a time, and deletes the unlinked records.
func (c *Cleanup) Run(ctx job.Context, _ job.Parameters) error {
	logger := ctx.GetLogger()
	if c.dao == nil {
		c.dao = scan.NewVulnerabilityRecordDao()
	}
	var total, cursor int64
	for {
		if cmd, ok := ctx.OPCommand(); ok && cmd == job.StopCommand {
			logger.Infof("Stopped after deleting %d unlinked vulnerability records", total)
			return nil
		}
		deleted, lastID, err := c.dao.DeleteUnlinked(ctx.SystemContext(), cursor, batchSize)
		if err != nil {
			logger.Errorf("Deleting unlinked vulnerability records after id %d failed: %v", cursor, err)
			return err
		}
		total += deleted
		if lastID == 0 {
			break
		}
		cursor = lastID
		time.Sleep(batchPause)
	}
	logger.Infof("Deleted %d unlinked vulnerability records", total)
	return nil
}
