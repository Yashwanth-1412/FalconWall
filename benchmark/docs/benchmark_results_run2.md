# Falcon Benchmark Results: Run 2

## Test configuration

Run 2 was performed between the two GCP C3 VMs using the existing benchmark
harness:

| Parameter | Value |
|---|---|
| RX VM | `10.190.0.5` (`falcon-rx`) |
| TX VM | `10.190.0.3` (`falcon-tx`) |
| Interface | `ens3` |
| Packet | 1400-byte UDP payload, 1442-byte Ethernet frame |
| Offered rates | 1.0M through 2.0M pps |
| Repetitions | 3 per backend/rate |
| Duration | 10 seconds offered traffic |
| Receiver CPU | CPU 0 |
| RX queues | 1 |

## Rate sweep

Values below are the captured three-run means. `Rx PPS` is the benchmark's
reported receive rate. The receiver was invoked with `expected_packets`, so
lossy runs could wait beyond the generator's 10-second window while waiting
for packets that would never arrive. Consequently, the PPS values at higher
loss rates are useful observations but are **not a clean saturation metric**.

| Offered | Socket Rx PPS | AF_PACKET Rx PPS | AF_XDP copy Rx PPS | AF_XDP ZC Rx PPS |
|---:|---:|---:|---:|---:|
| 1.0M | 503,892 | 484,053 | 1,000,031 | 1,000,006 |
| 1.2M | 336,613 | 488,067 | 1,200,496 | 1,200,494 |
| 1.4M | 198,192 | 484,115 | 1,400,587 | 1,400,569 |
| 1.6M | 92,163 | 492,114 | 1,600,018 | 1,600,007 |
| 1.8M | 54,956 | 493,839 | 1,778,692 | 1,762,751 |
| 2.0M | 48,473 | 549,511 | 1,478,174 | 1,793,038 |

### Loss and CPU means

| Offered | Socket loss / CPU | AF_PACKET loss / CPU | AF_XDP copy loss / CPU | AF_XDP ZC loss / CPU |
|---:|---:|---:|---:|---:|
| 1.0M | 24.4% / 48.3% | 27.4% / 49.3% | 0.0% / 24.3% | 0.0% / 44.3% |
| 1.2M | 57.7% / 47.7% | 39.0% / 48.3% | 0.0% / 41.3% | 0.0% / 35.0% |
| 1.4M | 78.6% / 47.7% | 48.1% / 52.3% | 0.0% / 43.7% | 0.0% / 39.3% |
| 1.6M | 91.3% / 49.7% | 53.8% / 52.3% | 0.0% / 39.0% | 0.0% / 32.7% |
| 1.8M | 95.4% / 49.7% | 58.7% / 50.3% | 0.0% / 30.7% | 0.0% / 51.3% |
| 2.0M | 96.4% / 55.0% | 58.6% / 56.3% | 0.0% / 33.0% | 0.0% / 46.0% |

## Findings

- The Run 2 socket result does **not** reproduce the earlier backwards result
  where 2M offered traffic appeared to receive more PPS than 1M.
- Socket throughput collapses as offered load increases: approximately 504K
  PPS at 1M, 337K at 1.2M, and below 100K by 1.6M.
- AF_PACKET remains near 484K to 550K reported PPS, with substantial loss.
- AF_XDP copy and zero-copy receive the full offered packet count through at
  least 1.8M pps in the captured runs. At 2M, AF_XDP zero-copy received all
  20M offered packets; AF_XDP copy missed only 1,348 packets across its three
  runs.
- The results establish that AF_XDP has not saturated by 1.8M pps, but they do
  **not** establish the exact saturation point at 2M because of the receiver
  timing flaw described below.

## Measurement issue discovered

`falcon-rxbench` stops on either elapsed time or `expected_packets`. For a
lossy backend, passing `expected_packets` can make the receiver continue after
the sender has stopped. Its final PPS is then divided by this extended drain
time. This explains unusually low values such as socket throughput at 1.8M
and the unstable AF_XDP copy value at 2M.

The next authoritative run should use a fixed receiver window and **not** pass
`expected_packets`. The sender's actual packet count should be recorded
separately, then loss should be calculated as:

```text
loss = offered_packets - received_packets
```

The payload-size sweep was started, but was intentionally stopped before
completion. No payload-size conclusions are included here.
