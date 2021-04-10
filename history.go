package main

import (
	"sync"
)

type result struct {
	id          int64
	moduleName  string
	target      string
	debugOutput string
	success     bool
}

// resultHistory contains two history slices: `results` contains most recent `maxResults` results.
// After they expire out of `results`, failures will be saved in `preservedFailedResults`. This
// ensures that we are always able to see debug information about recent failures.
type resultHistory struct {
	mu                     sync.Mutex
	nextId                 int64
	results                []*result
	preservedFailedResults []*result
	maxResults             uint
}

func (rh *resultHistory) Add(moduleName, target, debugOutput string, success bool) {
	rh.mu.Lock()
	defer rh.mu.Unlock()

	r := &result{
		id:          rh.nextId,
		moduleName:  moduleName,
		target:      target,
		debugOutput: debugOutput,
		success:     success,
	}
	rh.nextId++

	rh.results = append(rh.results, r)
	if uint(len(rh.results)) > rh.maxResults {
		// If we are about to remove a failure, add it to the failed result history, then
		// remove the oldest failed result, if needed.
		if !rh.results[0].success {
			rh.preservedFailedResults = append(rh.preservedFailedResults, rh.results[0])
			if uint(len(rh.preservedFailedResults)) > rh.maxResults {
				preservedFailedResults := make([]*result, len(rh.preservedFailedResults)-1)
				copy(preservedFailedResults, rh.preservedFailedResults[1:])
				rh.preservedFailedResults = preservedFailedResults
			}
		}
		results := make([]*result, len(rh.results)-1)
		copy(results, rh.results[1:])
		rh.results = results
	}
}

func (rh *resultHistory) List() []*result {
	rh.mu.Lock()
	defer rh.mu.Unlock()
	// TODO: why [:]?
	return append(rh.results[:], rh.preservedFailedResults...)
}

func (rh *resultHistory) Get(id int64) *result {
	rh.mu.Lock()
	defer rh.mu.Unlock()

	for _, r := range rh.results {
		if r.id == id {
			return r
		}
	}
	for _, r := range rh.preservedFailedResults {
		if r.id == id {
			return r
		}
	}

	return nil
}
