// sentinel-smoke loads the Kernel Sentinel, sends a pulse, reads back
// any prior absence events, and prints a summary. Safe to run
// repeatedly — it reattaches to the pinned objects.
//
//	sudo ./bin/sentinel-smoke           # one-shot: load + pulse + drain
//	sudo ./bin/sentinel-smoke --pulse   # loop: pulse every 30s forever
//	sudo ./bin/sentinel-smoke --drain   # just drain absence ringbuf

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/963causal/agent/internal/sentinel"
)

func main() {
	pulse := flag.Bool("pulse", false, "pulse forever until interrupted")
	drainOnly := flag.Bool("drain", false, "drain absences and exit")
	unpin := flag.Bool("unpin", false, "remove pinned bpf objects and exit")
	flag.Parse()

	if *unpin {
		if err := sentinel.Unpin(); err != nil {
			log.Fatalf("unpin: %v", err)
		}
		fmt.Println("unpinned /sys/fs/bpf/963causal/*")
		return
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	s, err := sentinel.Open(ctx)
	if err != nil {
		log.Fatalf("open sentinel: %v", err)
	}
	defer s.Close()

	evts, err := s.DrainAbsences()
	if err != nil {
		log.Fatalf("drain: %v", err)
	}
	fmt.Printf("drained %d absence events\n", len(evts))
	for i, e := range evts {
		if e.NeverSawPulse {
			fmt.Printf("  [%d] detected=%s  never_saw_pulse  cpu=%d\n",
				i, e.DetectedAt.Format(time.RFC3339), e.Cpu)
		} else {
			fmt.Printf("  [%d] detected=%s  last_seen=%s  gap=%.1fs  cpu=%d  comm=%q  seq=%d\n",
				i, e.DetectedAt.Format(time.RFC3339),
				e.AgentLastSeen.Format(time.RFC3339),
				e.GapSeconds, e.Cpu, e.Comm, e.LastSeq)
		}
	}

	if *drainOnly {
		return
	}

	// Send an initial pulse so the timer has a fresh reference.
	if err := s.Pulse(time.Now()); err != nil {
		log.Fatalf("pulse: %v", err)
	}
	fmt.Println("pulse sent")

	if !*pulse {
		return
	}

	tick := time.NewTicker(sentinel.PulseInterval)
	defer tick.Stop()
	fmt.Printf("pulsing every %s. Ctrl-C to stop (sentinel will detect absence after 120s)\n",
		sentinel.PulseInterval)
	for {
		select {
		case <-ctx.Done():
			fmt.Println("bye — sentinel remains pinned in /sys/fs/bpf/963causal/")
			return
		case t := <-tick.C:
			if err := s.Pulse(t); err != nil {
				log.Printf("pulse error: %v", err)
			} else {
				fmt.Printf("pulse @ %s\n", t.Format(time.RFC3339))
			}
		}
	}
}
