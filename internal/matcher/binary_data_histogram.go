package matcher

import (
	"encoding/binary"
	"math"
)

type OutlierDetector struct {
	n                 int
	sum               float64
	sumOfSquares      float64
	mean              float64
	standardDeviation float64
}

func NewOutlierDetector() *OutlierDetector {
	return &OutlierDetector{}
}

func (d *OutlierDetector) Add(sample float64) {
	d.n++
	d.sum += sample
	d.sumOfSquares += sample * sample
}

func (d *OutlierDetector) Prepare() {
	if d.n > 0 {
		d.mean = d.sum / float64(d.n)
		denom := max(d.n-1, 1)
		d.standardDeviation = math.Sqrt((d.sumOfSquares - d.sum*d.mean) / float64(denom))
	}
}

func (d *OutlierDetector) DecideOutlier(sample float64) int {
	const minTolerance = 0.1
	const sigmaBound = 1.9

	if d.n <= 1 {
		return 0
	}
	tolerance := math.Max(minTolerance, d.standardDeviation)
	numSigma := (sample - d.mean) / tolerance
	if numSigma > sigmaBound {
		return 1
	}
	if numSigma < -sigmaBound {
		return -1
	}
	return 0
}

type BinaryDataHistogram struct {
	size      int
	histogram []int32
}

func NewBinaryDataHistogram() *BinaryDataHistogram {
	return &BinaryDataHistogram{}
}

func (h *BinaryDataHistogram) Compute(region []byte) bool {
	if len(region) < 2 {
		return false
	}
	if len(h.histogram) != 65536 {
		h.histogram = make([]int32, 65536)
	} else {
		clear(h.histogram)
	}
	h.size = len(region)
	bound := h.size - 1
	for i := range bound {
		val := binary.LittleEndian.Uint16(region[i:])
		h.histogram[val]++
	}
	return true
}

func (h *BinaryDataHistogram) IsValid() bool {
	return h.histogram != nil
}

func (h *BinaryDataHistogram) Distance(other *BinaryDataHistogram) float64 {
	if !h.IsValid() || !other.IsValid() {
		return 1.0
	}
	var totalDiff float64 = 0
	for i := range 65536 {
		diff := float64(h.histogram[i] - other.histogram[i])
		totalDiff += math.Abs(diff)
	}
	return totalDiff / float64(h.size+other.size)
}
