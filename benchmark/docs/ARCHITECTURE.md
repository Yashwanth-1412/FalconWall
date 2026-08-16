# Falcon Architecture

## The one idea

Falcon benchmarks the Linux packet I/O stack **from top to bottom** by running
the *same* workload against progressively lower-level backends:

```
   ┌────────────────────────────────────┐  POSIX Socket   recv/recvmmsg — full
   │       kernel protocol stack       │                  kernel stack, L4
   ├────────────────────────────────────┤
   │         AF_PACKET (raw L2)        │  send/recv on raw sockets — access
   │                                    │  to the link layer, still through
   │                                    │  the kernel
   ├────────────────────────────────────┤
   │   AF_XDP (copy mode)              │  userspace packet I/O using UMEM-
   │                                    │  backed buffers
   ├────────────────────────────────────┤
   │   AF_XDP (zero-copy)              │  ... with zero-copy when supported
   │                                    │  by the NIC and driver — lowest
   │                                    │  level Falcon reaches
   └────────────────────────────────────┘
```

Every backend answers the same question: **how fast can packets get into your
process, and at what latency and CPU cost?**

## Compile-time backend selection (no vtable in the hot path)

Backends are selected at **compile time** via templates / CRTP (static
polymorphism). No virtual dispatch on the receive path.

```cpp
// The contract: each backend implements these, same signature, no base class.
// A CRTP base and/or static_asserts enforce the shape.
struct SocketBackend  { size_t recv(Frame* out, size_t max); Stats stats() const; };
struct AfPacketBackend{ size_t recv(Frame* out, size_t max); Stats stats() const; };
struct AfXdpBackend   { size_t recv(Frame* out, size_t max); Stats stats() const; };

// Consumers are templated on the backend type — the compiler sees the
// concrete backend at each call site.
template <class Backend>
void run_receive_loop(Backend& backend, ...) { ... backend.recv(...); ... }
```

## The backend-independent pipeline

The processing pipeline never knows which backend it runs on. Only the packet
I/O step changes:

```
   Receive
     │        ← PacketIO: only this step is backend-specific
     ▼
   Parse
     │        ← shared parser: Ethernet → IPv4 → TCP/UDP, zero-copy
     ▼
   Process
     │        ← user callback / protocol logic (benchmark workload)
     ▼
   Statistics
     │        ← packets, bytes, drops, latency percentiles
     ▼
   Transmit   ← optional: only backends that support it
```

## Shared zero-copy parser

One parser, used by **every** backend. It parses directly from the packet
buffer — slicing `uint8_t*` regions, never copying or allocating:

```
 Frame (data, len)
   └─ ethernet header  → ethernet.hpp
       └─ ipv4 header  → ipv4.hpp
           └─ tcp | udp header → tcp.hpp / udp.hpp
```

Backend, parser and pipeline are three independent layers that only meet at
the `Frame` type.

## Benchmark matrix

Same workload, four configurations, one harness:

| Backend | pps | p50 latency | p99 latency | CPU usage | drops |
|---|---|---|---|---|---|
| POSIX Socket | | | | | |
| AF_PACKET | | | | | |
| AF_XDP (copy mode) | | | | | |
| AF_XDP (zero-copy, when supported) | | | | | |

- **Throughput** — packets/sec over a stats window (xdp-bench style).
- **Latency** — p50/p99 round-trip or receive-to-process time.
- **CPU usage** — busy vs. idle wait (epoll vs busy-poll matters here).
- **Packet drops** — reported per-backend (kernel drops, ring drops, drops).

## Current layout

```
Falcon/
├── CMakeLists.txt
├── include/falcon/
│   ├── core/stats.hpp            # Stats counters (exists)
│   ├── backend/                  # SocketBackend / AfPacketBackend / AfXdpBackend
│   ├── parser/                   # ethernet / ipv4 / tcp / udp
│   ├── pipeline/                 # receive → parse → process → stats → tx
│   └── traffic/                  # benchmark traffic generator
├── src/
│   ├── core/
│   └── backend/
├── bench/bench_main.cpp          # falcon-bench (stub)
├── examples/recv_demo.cpp        # falcon-recv  (stub)
└── tests/
```

## Milestones

| # | Deliverable | Benchmarkable |
|---|---|---|
| 1 | Compile-time backend contract (CRTP base + `Frame`) | — |
| 2 | SocketBackend (`recvmmsg`) | via `falcon-recv` |
| 3 | Shared parser (eth/ipv4/tcp/udp) + pipeline | — |
| 4 | Bench harness (pps, p50/p99, CPU) + traffic generator | Socket |
| 5 | AfPacketBackend (raw L2) | Socket + AF_PACKET |
| 6 | AfXdpBackend (copy mode → zero-copy) | all four |
| 7 | Full comparison report across the matrix | all four |

The pay-off: one table with four rows, real numbers, and a one-paragraph
explanation of *where each layer's latency lives*. That is the resume story.
