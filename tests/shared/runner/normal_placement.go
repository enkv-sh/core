package main

import (
	"math"
	"slices"
	"strings"
)

type normalPlacementItem struct {
	key              string
	estimatedSeconds float64
}

func normalPlacement(items []normalPlacementItem, parallel int) [][]int {
	if len(items) == 0 {
		return nil
	}
	seconds := func(index int) float64 {
		value := items[index].estimatedSeconds
		if value <= 0 || math.IsNaN(value) || math.IsInf(value, 0) {
			return 1
		}
		return value
	}
	order := make([]int, len(items))
	for index := range order {
		order[index] = index
	}
	slices.SortFunc(order, func(left, right int) int {
		if seconds(left) > seconds(right) {
			return -1
		}
		if seconds(left) < seconds(right) {
			return 1
		}
		return strings.Compare(items[left].key, items[right].key)
	})
	groups := make([][]int, min(parallel, len(items)))
	weights := make([]float64, len(groups))
	for _, index := range order {
		least := 0
		for next := 1; next < len(groups); next++ {
			if weights[next] < weights[least] {
				least = next
			}
		}
		groups[least] = append(groups[least], index)
		weights[least] += seconds(index)
	}
	return groups
}

func testEstimate(estimates map[string]float64, name string) float64 {
	if seconds := estimates[name]; seconds > 0 && !math.IsNaN(seconds) && !math.IsInf(seconds, 0) {
		return seconds
	}
	// Unknown tests remain selected. A small positive estimate spreads them
	// across groups without requiring a timing record before they can run.
	return 1
}
