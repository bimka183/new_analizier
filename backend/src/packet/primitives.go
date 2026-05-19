package packet

import (
	"math"
	"sort"
)

const MinSampleSize = 5

// Mean вычисляет среднее арифметическое
func Mean(values []float64) (float64, bool) {
	if len(values) < MinSampleSize {
		return 0, false
	}
	
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values)), true
}

// StdDev вычисляет выборочное стандартное отклонение (делитель N-1)
func StdDev(values []float64) (float64, bool) {
	if len(values) < MinSampleSize {
		return 0, false
	}
	
	mean, ok := Mean(values)
	if !ok {
		return 0, false
	}
	
	var sumSq float64
	for _, v := range values {
		diff := v - mean
		sumSq += diff * diff
	}
	
	variance := sumSq / float64(len(values)-1)
	return math.Sqrt(variance), true
}

// ZScore вычисляет Z-score текущего значения относительно истории
func ZScore(current float64, history []float64) (float64, bool) {
	if len(history) < MinSampleSize {
		return 0, false
	}
	
	mean, ok := Mean(history)
	if !ok {
		return 0, false
	}
	
	stdDev, ok := StdDev(history)
	if !ok || stdDev == 0 {
		return 0, false
	}
	
	return (current - mean) / stdDev, true
}

// Percentile вычисляет указанный перцентиль (линейная интерполяция)
func Percentile(values []float64, p float64) (float64, bool) {
	if len(values) == 0 {
		return 0, false
	}
	
	if p < 0 || p > 100 {
		return 0, false
	}
	
	sorted := make([]float64, len(values))
	copy(sorted, values)
	sort.Float64s(sorted)
	
	if p == 0 {
		return sorted[0], true
	}
	if p == 100 {
		return sorted[len(sorted)-1], true
	}
	
	idx := (p / 100) * float64(len(sorted)-1)
	lower := int(math.Floor(idx))
	upper := int(math.Ceil(idx))
	
	if lower == upper {
		return sorted[lower], true
	}
	
	weight := idx - float64(lower)
	return sorted[lower]*(1-weight) + sorted[upper]*weight, true
}

// IQR вычисляет межквартильный размах
func IQR(values []float64) (float64, bool) {
	if len(values) < 4 {
		return 0, false
	}
	
	q1, ok := Percentile(values, 25)
	if !ok {
		return 0, false
	}
	
	q3, ok := Percentile(values, 75)
	if !ok {
		return 0, false
	}
	
	return q3 - q1, true
}

// Median вычисляет медиану
func Median(values []float64) (float64, bool) {
	if len(values) == 0 {
		return 0, false
	}
	
	sorted := make([]float64, len(values))
	copy(sorted, values)
	sort.Float64s(sorted)
	
	n := len(sorted)
	if n%2 == 0 {
		return (sorted[n/2-1] + sorted[n/2]) / 2, true
	}
	return sorted[n/2], true
}

// MAD вычисляет медианное абсолютное отклонение
func MAD(values []float64) (float64, bool) {
	if len(values) < MinSampleSize {
		return 0, false
	}
	
	median, ok := Median(values)
	if !ok {
		return 0, false
	}
	
	absDeviations := make([]float64, len(values))
	for i, v := range values {
		absDeviations[i] = math.Abs(v - median)
	}
	
	mad, ok := Median(absDeviations)
	if !ok {
		return 0, false
	}
	
	return mad, true
}

// EWMA вычисляет экспоненциальное скользящее среднее
func EWMA(values []float64, alpha float64) (float64, bool) {
	if len(values) == 0 {
		return 0, false
	}
	
	if alpha <= 0 || alpha > 1 {
		alpha = 0.3
	}
	
	ewma := values[0]
	for i := 1; i < len(values); i++ {
		ewma = alpha*values[i] + (1-alpha)*ewma
	}
	
	return ewma, true
}

// RelativeGrowth вычисляет относительный рост
func RelativeGrowth(current, previous float64) float64 {
	if previous < 1 {
		previous = 1
	}
	return current / previous
}