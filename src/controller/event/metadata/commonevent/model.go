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

package commonevent

import (
	"context"
	"net/url"
	"regexp"
	"sync"

	eventmodel "github.com/goharbor/harbor/src/controller/event/model"
	"github.com/goharbor/harbor/src/pkg/notifier/event"
)

// Resolver the interface to resolve Metadata to CommonEvent
type Resolver interface {
	Resolve(*Metadata, *event.Event) error
	PreCheck(ctx context.Context, url string, method string) (bool, string)
}

<<<<<<< HEAD
// Snapshotter is implemented by resolvers that need state from before the
// request is handled, such as the values an update overwrites.
type Snapshotter interface {
	Snapshot(ctx context.Context, payload string) any
}

var urlResolvers = map[string]Resolver{}
=======
type registration struct {
	pattern  *regexp.Regexp
	resolver Resolver
}

var registrations = map[string]registration{}
>>>>>>> 3cc8b5c16 (Compile audit resolver patterns once (#24476))

var mu = &sync.Mutex{}

// RegisterResolver register a resolver for a specific URL pattern
func RegisterResolver(urlPattern string, resolver Resolver) {
	p := regexp.MustCompile(urlPattern)
	mu.Lock()
	defer mu.Unlock()
	registrations[urlPattern] = registration{pattern: p, resolver: resolver}
}

<<<<<<< HEAD
// UnregisterResolver removes the resolver registered for a URL pattern
func UnregisterResolver(urlPattern string) {
	mu.Lock()
	delete(urlResolvers, urlPattern)
	mu.Unlock()
}

// Resolvers returns a snapshot of the registered resolvers, safe to range over
// while resolvers are registered or unregistered concurrently
func Resolvers() map[string]Resolver {
	mu.Lock()
	defer mu.Unlock()
	snapshot := make(map[string]Resolver, len(urlResolvers))
	for urlPattern, resolver := range urlResolvers {
		snapshot[urlPattern] = resolver
	}
	return snapshot
=======
// Resolvers returns a copy of the registered resolvers keyed by URL pattern
func Resolvers() map[string]Resolver {
	mu.Lock()
	defer mu.Unlock()
	resolvers := make(map[string]Resolver, len(registrations))
	for urlPattern, reg := range registrations {
		resolvers[urlPattern] = reg.resolver
	}
	return resolvers
>>>>>>> 3cc8b5c16 (Compile audit resolver patterns once (#24476))
}

// Metadata the raw data of event
type Metadata struct {
	// Ctx ...
	Ctx context.Context
	// Username requester username
	Username string
	// RequestPayload http request payload
	RequestPayload string
	// RequestMethod
	RequestMethod string
	// ResponseCode response code
	ResponseCode int
	// RequestURL request URL
	RequestURL string
	// IsResourceName indicates the request declared, via the X-Is-Resource-Name
	// header, that name/ID path parameters are resource names
	IsResourceName bool
	// IPAddress IP address of the request
	IPAddress string
	// UserAgent is the User-Agent header of the request
	UserAgent string
	// ResponseLocation response location
	ResponseLocation string
	// ResourceName resource name
	ResourceName string
	// Payload request payload
	Payload string
	// Before is what the resolver's Snapshot captured before the request ran
	Before any
}

// Resolve parse the audit information from CommonEventMetadata
func (c *Metadata) Resolve(event *event.Event) error {
<<<<<<< HEAD
	resolver, metadata, ok := c.resolver()
	if !ok {
		return nil
	}
	if err := resolver.Resolve(metadata, event); err != nil {
		return err
	}
	// stamp the request's client IP/User-Agent onto the resolved event
	// here rather than in every resolver, so it's captured uniformly
	if common, ok := event.Data.(*eventmodel.CommonEvent); ok {
		common.SourceIP = c.IPAddress
		common.UserAgent = c.UserAgent
=======
	for _, reg := range registrations {
		if reg.pattern.MatchString(c.RequestURL) {
			return reg.resolver.Resolve(c, event)
		}
>>>>>>> 3cc8b5c16 (Compile audit resolver patterns once (#24476))
	}
	return nil
}

// PreCheck check if current event is matched and return the prefetched resource name when it is delete operation
func (c *Metadata) PreCheckMetadata() (bool, string) {
<<<<<<< HEAD
	resolver, metadata, ok := c.resolver()
	if ok {
		return resolver.PreCheck(metadata.Ctx, metadata.RequestURL, metadata.RequestMethod)
=======
	for _, reg := range registrations {
		if reg.pattern.MatchString(c.RequestURL) {
			return reg.resolver.PreCheck(c.Ctx, c.RequestURL, c.RequestMethod)
		}
>>>>>>> 3cc8b5c16 (Compile audit resolver patterns once (#24476))
	}
	return false, ""
}

// Snapshot lets the matched resolver capture state before the request is handled.
func (c *Metadata) Snapshot(payload string) {
	resolver, metadata, ok := c.resolver()
	if !ok {
		return
	}
	if s, ok := resolver.(Snapshotter); ok {
		c.Before = s.Snapshot(metadata.Ctx, payload)
	}
}

func (c *Metadata) resolver() (Resolver, *Metadata, bool) {
	metadata := *c
	if requestURL, err := url.Parse(c.RequestURL); err == nil {
		metadata.RequestURL = requestURL.Path
	}

	for urlPattern, resolver := range Resolvers() {
		match := patternRegexp(urlPattern).FindStringIndex(metadata.RequestURL)
		if match != nil && match[0] == 0 && match[1] == len(metadata.RequestURL) {
			return resolver, &metadata, true
		}
	}
	return nil, &metadata, false
}

// compiledPatterns caches resolver URL patterns; the log middleware matches
// every request against all of them.
var compiledPatterns sync.Map

func patternRegexp(urlPattern string) *regexp.Regexp {
	if re, ok := compiledPatterns.Load(urlPattern); ok {
		return re.(*regexp.Regexp)
	}
	re, _ := compiledPatterns.LoadOrStore(urlPattern, regexp.MustCompile(urlPattern))
	return re.(*regexp.Regexp)
}
