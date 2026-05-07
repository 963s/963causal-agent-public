// cusum-simulate runs the boiling-frog detection experiment the
// user's threat-model memo describes, end-to-end and reproducibly.
//
// Scenario:
//
//   Day 0      : PAL enrolment on a 224-bit reliable pool.
//   Days 1..7  : calibration burst. CUSUM learns the baseline
//                natural-noise mean and stddev.
//   Days 8..30 : adversary flips each bit with probability
//                p0 + day*attack_per_day, where p0 is the
//                calibrated BER and attack_per_day defaults to
//                0.01 (the specific 1 %/day rate the threat
//                memo asked the detector to catch).
//
// Exit code 0 iff the CUSUM detector fires on or before day 15
// (the "well before the attacker can flip the fingerprint"
// guarantee the threat analysis claimed). Exit 1 if the detector
// needs longer.
//
// Prints a per-day line so an operator can visualise the
// statistic's growth:
//
//   day 01  h= 0  S⁺= 0.00   [OK]
//   day 02  h= 1  S⁺= 0.00   [OK]
//   day 03  h= 6  S⁺= 4.88   [OK]
//   day 04  h=12  S⁺=14.88   [BROAD_DRIFT]   ← alarm
package main

import (
	"flag"
	"fmt"
	"math/rand"
	"os"
	"strings"

	"github.com/963causal/agent/internal/puf"
)

func main() {
	nBits := flag.Int("bits", 224, "reliable-bit pool size")
	p0 := flag.Float64("baseline-ber", 0.005, "per-bit BER under legitimate noise")
	attackPerDay := flag.Float64("attack-per-day", 0.01, "per-bit BER shift added each day after calibration")
	days := flag.Int("days", 30, "simulated days after enrolment")
	calDays := flag.Int("calibration-days", 40, "days used to calibrate μ/σ before the attack begins")
	seed := flag.Int64("seed", 0xFEEDFACE, "RNG seed")
	alarmBy := flag.Int("alarm-by", 15, "fail the exit code if no alarm fires by this day")
	flag.Parse()

	rng := rand.New(rand.NewSource(*seed))

	// ---- Calibration (natural noise only) ---------------------
	calib := make([][]bool, *calDays)
	for i := range calib {
		calib[i] = sample(rng, *nBits, *p0)
	}
	c, err := puf.Calibrate(calib)
	if err != nil {
		fmt.Fprintf(os.Stderr, "calibrate: %v\n", err)
		os.Exit(2)
	}
	fmt.Printf("calibrated on %d days: μ=%.2f bits σ=%.3f bits k_agg=%.3f H_agg=%.3f\n",
		*calDays, c.Mu, c.Sigma, c.K, c.H)
	fmt.Printf("attack scenario: +%.1f%% BER per day on all %d reliable bits\n",
		*attackPerDay*100, *nBits)
	fmt.Println()

	// ---- Simulation -----------------------------------------
	firstAlarmDay := 0
	for day := 1; day <= *days; day++ {
		p := *p0 + float64(day)*(*attackPerDay)
		if p > 1 {
			p = 1
		}
		delta := sample(rng, *nBits, p)
		v, err := c.Observe(delta)
		if err != nil {
			fmt.Fprintf(os.Stderr, "observe day %d: %v\n", day, err)
			os.Exit(2)
		}
		tag := v.Level
		arrow := ""
		if v.AggregateFired || v.PerBitFired {
			if firstAlarmDay == 0 {
				firstAlarmDay = day
				arrow = "   ← alarm"
			}
		}
		fmt.Printf("day %02d  h=%3d  S⁺_agg=%6.2f  S⁺_bit_max=%5.2f  drifting_bits=%2d  [%s]%s\n",
			day, v.HammingDistance,
			v.AggregatePlus, v.MaxPerBitPlus,
			v.DriftingBitCount, tag, arrow)
	}
	fmt.Println()

	// ---- Verdict ---------------------------------------------
	if firstAlarmDay == 0 {
		fmt.Println("VERDICT: no alarm fired within the simulation horizon — CUSUM FAILED.")
		os.Exit(1)
	}
	verdict := "PASS"
	if firstAlarmDay > *alarmBy {
		verdict = "TOO SLOW"
	}
	line := fmt.Sprintf("VERDICT: %s — first alarm on day %d (threshold ≤ %d)",
		verdict, firstAlarmDay, *alarmBy)
	fmt.Println(strings.Repeat("-", len(line)))
	fmt.Println(line)
	fmt.Println(strings.Repeat("-", len(line)))
	if firstAlarmDay > *alarmBy {
		os.Exit(1)
	}
}

func sample(rng *rand.Rand, n int, p float64) []bool {
	out := make([]bool, n)
	for i := range out {
		out[i] = rng.Float64() < p
	}
	return out
}
