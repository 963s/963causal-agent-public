// SPDX-License-Identifier: GPL-2.0
//
// 963causal Kernel Sentinel
// -----------------------
// A userspace-killable dead-man's switch. The agent writes a heartbeat
// into `pulse_map` every ~30s. A kernel BPF_TIMER fires periodically
// (independent of any agent process); if the last pulse is older than
// PULSE_TIMEOUT_NS it records an `absence_event` on a ringbuf.
//
// When the agent starts up (or restarts after a kill -9 + respawn) it
// drains the ringbuf and ships the contents to the server. Because the
// timer and ringbuf are pinned in /sys/fs/bpf/, they survive the
// agent's death as long as the kernel is alive.
//
// Design notes:
//   * No tracepoint on sys_enter_write — that path is too noisy and
//     records the wrong thing. Only the timer callback emits events.
//   * `bpf_get_current_*` helpers are unreliable inside timer callbacks
//     because there is no meaningful "current" task: we still call
//     them for forensic hints, but the server treats them as lossy.
//   * Everything is CO-RE friendly: we only depend on the ktime helper
//     and basic map ops, which have been stable since 5.15.

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// vmlinux.h only ships `struct bpf_timer_kern`; the uapi opaque
// `struct bpf_timer` is 16 bytes, aligned to 8. Declare it here so
// libbpf helper prototypes resolve.
struct bpf_timer {
    __u64 _opaque[2];
} __attribute__((aligned(8)));

#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC 1
#endif
#ifndef EBUSY
#define EBUSY 16
#endif

#define NSEC_PER_SEC 1000000000ULL

// Timer tick period. The server considers pulses older than
// PULSE_TIMEOUT_NS as "absent". We choose 120s so we tolerate routine
// restarts and GC pauses but catch sustained death.
#define TIMER_PERIOD_NS  (30ULL * NSEC_PER_SEC)
#define PULSE_TIMEOUT_NS (120ULL * NSEC_PER_SEC)

// Per-host boot identity. The agent writes its host_id once at load
// time; the timer reads it when synthesising absence events so the
// server can correlate without the agent being alive to tag them.
struct pulse_key {
    __u32 host_id;
};

// What the agent writes as a heartbeat.
struct pulse_value {
    __u64 timestamp_ns;   // bpf_ktime_get_ns() at the moment of pulse
    __u64 wallclock_ns;   // Go's time.Now().UnixNano() — for forensics
    __u64 seq;            // monotonic counter from userspace
};

// What the timer records when the agent is silent.
struct absence_event {
    __u64 now_ns;
    __u64 last_pulse_ns;
    __u64 last_wallclock_ns;
    __u64 last_seq;
    __u32 cpu;
    __u32 flags;          // 0x01 = never_saw_pulse
    __u8  comm[16];       // best-effort task comm at timer fire
};

// pulse_map: at most one entry (host_id 0). Using HASH keeps us honest
// about lookups even when the agent hasn't populated it yet.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, struct pulse_key);
    __type(value, struct pulse_value);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} pulse_map SEC(".maps");

// absence_ringbuf: 256 KiB circular buffer. On a well-behaved system
// this should remain nearly empty; when full we drop the oldest by
// design (BPF_RB_NO_WAKEUP semantics).
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} absence_ringbuf SEC(".maps");

// The timer storage. BPF_TIMER is kernel-scheduled and survives
// userspace crashes.
struct timer_elem {
    struct bpf_timer t;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct timer_elem);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} timer_map SEC(".maps");

// Force BTF emission for the user-facing structs so bpf2go can mirror
// them into Go. `absence_event` would otherwise be optimised out
// because it is only referenced through ringbuf reserve.
struct pulse_key      *__eidolon_t_pulse_key      __attribute__((unused));
struct pulse_value    *__eidolon_t_pulse_value    __attribute__((unused));
struct absence_event  *__eidolon_t_absence_event  __attribute__((unused));

static __always_inline void emit_absence(__u64 now_ns,
                                         const struct pulse_value *p)
{
    struct absence_event *evt = bpf_ringbuf_reserve(&absence_ringbuf,
                                                    sizeof(*evt), 0);
    if (!evt)
        return;

    evt->now_ns = now_ns;
    if (p) {
        evt->last_pulse_ns     = p->timestamp_ns;
        evt->last_wallclock_ns = p->wallclock_ns;
        evt->last_seq          = p->seq;
        evt->flags             = 0;
    } else {
        evt->last_pulse_ns     = 0;
        evt->last_wallclock_ns = 0;
        evt->last_seq          = 0;
        evt->flags             = 0x01; // never_saw_pulse
    }
    evt->cpu = bpf_get_smp_processor_id();
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    bpf_ringbuf_submit(evt, 0);
}

static int check_pulse_cb(void *map, int *key, struct timer_elem *te)
{
    (void)map;
    (void)key;

    struct pulse_key pk = { .host_id = 0 };
    struct pulse_value *p = bpf_map_lookup_elem(&pulse_map, &pk);
    __u64 now = bpf_ktime_get_ns();

    // Two absence conditions:
    //   (a) no pulse ever recorded, and we have been alive > PULSE_TIMEOUT
    //       — handled at start-up elsewhere; here we treat it as missing.
    //   (b) pulse exists but its age exceeds PULSE_TIMEOUT.
    if (!p || now - p->timestamp_ns > PULSE_TIMEOUT_NS) {
        emit_absence(now, p);
    }

    // Re-arm.
    bpf_timer_start(&te->t, TIMER_PERIOD_NS, 0);
    return 0;
}

// start_timer is a BPF_PROG_TYPE_SYSCALL program: userspace invokes it
// once with BPF_PROG_RUN after pinning the timer map. It initialises
// the timer and schedules the first fire.
SEC("syscall")
int start_timer(void *ctx)
{
    (void)ctx;

    __u32 zero = 0;
    struct timer_elem *te = bpf_map_lookup_elem(&timer_map, &zero);
    if (!te)
        return -1;

    long ret = bpf_timer_init(&te->t, &timer_map, CLOCK_MONOTONIC);
    if (ret && ret != -EBUSY)
        return (int)ret;
    ret = bpf_timer_set_callback(&te->t, check_pulse_cb);
    if (ret)
        return (int)ret;
    ret = bpf_timer_start(&te->t, TIMER_PERIOD_NS, 0);
    if (ret)
        return (int)ret;

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
