package main

import (
	"fmt"
	"testing"
)

func TestHistoryKeepsLatestResults(t *testing.T) {
	history := &resultHistory{maxResults: 3}
	for i := 0; i < 4; i++ {
		history.Add("module", "target", fmt.Sprintf("result %d", i), true)
	}

	savedResults := history.List()
	for i := 0; i < len(savedResults); i++ {
		if savedResults[i].debugOutput != fmt.Sprintf("result %d", i+1) {
			t.Errorf("History contained the wrong result at index %d", i)
		}
	}
}

func FillHistoryWithMaxSuccesses(h *resultHistory) {
	for i := 0; i < int(h.maxResults); i++ {
		h.Add("module", "target", fmt.Sprintf("result %d", h.nextId), true)
	}
}

func FillHistoryWithMaxPreservedFailures(h *resultHistory) {
	for i := 0; i < int(h.maxResults); i++ {
		h.Add("module", "target", fmt.Sprintf("result %d", h.nextId), false)
	}
}

func TestHistoryPreservesExpiredFailedResults(t *testing.T) {
	history := &resultHistory{maxResults: 3}

	FillHistoryWithMaxSuccesses(history)
	FillHistoryWithMaxPreservedFailures(history)
	savedResults := history.List()
	for i := uint(0); i < uint(len(savedResults)); i++ {
		expectedDebugOutput := fmt.Sprintf("result %d", i+history.maxResults)
		if savedResults[i].debugOutput != expectedDebugOutput {
			t.Errorf("History contained the wrong result at index %d. Expected %s, Actual: %s", i, expectedDebugOutput, savedResults[i].debugOutput)
		}
	}

	FillHistoryWithMaxPreservedFailures(history)
	savedResults = history.List()
	for i := uint(0); i < uint(len(savedResults)); i++ {
		expectedDebugOutput := fmt.Sprintf("result %d", i+history.maxResults)
		if savedResults[i].debugOutput != expectedDebugOutput {
			t.Errorf("History contained the wrong result at index %d. Expected %s, Actual: %s", i, expectedDebugOutput, savedResults[i].debugOutput)
		}
	}

	FillHistoryWithMaxPreservedFailures(history)
	FillHistoryWithMaxSuccesses(history)
	savedResults = history.List()
	for i := uint(0); i < uint(len(savedResults)); i++ {
		expectedDebugOutput := fmt.Sprintf("result %d", i+history.maxResults*3)
		if savedResults[i].debugOutput != expectedDebugOutput {
			t.Errorf("History contained the wrong result at index %d. Expected %s, Actual: %s", i, expectedDebugOutput, savedResults[i].debugOutput)
		}
	}
}
