# Saturation Benchmark

`falcon-rxbench` measures receive throughput only. Its hot loop does not parse
packets, inspect timestamps, retain frames, allocate memory, or calculate latency.
It prints CSV rows with elapsed time, packets per second, and Gigabits per second.

```sh
sudo taskset -c 2 ./build/falcon-rxbench xdp ens4 30
sudo taskset -c 2 ./build/falcon-rxbench xdp-zc ens4 5
sudo taskset -c 2 ./build/falcon-rxbench packet ens4 30
sudo taskset -c 2 ./build/falcon-rxbench socket 9100 30
```

For a one-queue native copy-mode AF_XDP baseline, force one NIC queue on the
receiver and send benchmark UDP traffic to port 9100 from a same-zone generator.

```sh
sudo ethtool -L ens4 combined 1
sudo ./build/falcon-rxbench xdp ens4 30
```

Run a 30-second rate sweep from the generator, increasing offered pps each run.
The saturation point is the first offered rate at which received pps stops
increasing or kernel drops become non-zero. Compare each backend with the same
queue count, CPU pinning, packet size, duration, and offered rate.

`falcon-rxbench` reports AF_PACKET and AF_XDP kernel drops at the end of a run.
Socket kernel-drop reporting requires receiving ancillary `SO_RXQ_OVFL` messages,
which would add work to its receive loop, so it is intentionally not enabled here.

`xdp-zc` is a capability probe. It forces `XDP_ZEROCOPY` and fails rather than
falling back to copy mode when the driver does not support AF_XDP zero-copy.

For a finite controlled generator run, append the offered packet count. The
receiver then stops immediately after that count rather than including idle
drain time in its final average.

```sh
sudo ./build/falcon-rxbench xdp ens4 30 800000
```

On a generator with the kernel `pktgen` module, use the included helper for
IPv4 UDP traffic. It emits 64 source-port flows and targets queue zero.

```sh
sudo ./scripts/pktgen_udp.sh ens3 <receiver-mac> <tx-ip> <rx-ip> 1400 1000000 30
```

Sweep the sixth argument from 250000 through 8000000 pps. Use the same offered
rate for every backend. The package version of `xdp-trafficgen` on Ubuntu 24.04
may fail on GCP kernels when loading optional tracepoint programs; `pktgen` avoids
that compatibility dependency.
