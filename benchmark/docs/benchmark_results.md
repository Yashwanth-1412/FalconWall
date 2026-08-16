# Falcon Benchmark Results

## Test Configuration

| Parameter | Value |
|-----------|-------|
| **Date** | 2026-08-16 |
| **RX VM** | falcon-rx (10.190.0.5), GCP C3, 4 vCPU |
| **TX VM** | falcon-tx (10.190.0.3), GCP C3, 4 vCPU |
| **NIC** | gVNIC (ens3), 23 Gb/s link |
| **Kernel** | 6.17.0-1022-gcp |
| **Queues** | 1 RX / 1 TX |
| **Ring Buffer** | 4096 RX / 4096 TX |
| **Packet Size** | 1400-byte UDP payload (1442 bytes on wire) |
| **Flows** | 64 randomized UDP source ports |
| **Duration** | 10 seconds per test |
| **CPU Pinning** | Core 0 for receiver |

## Results: 1M pps Offered Rate

### Throughput & Loss

| Backend | Received PPS | Loss % | Bandwidth (Gb/s) | CPU % |
|---------|-------------|--------|------------------|-------|
| **Socket** | 752,472 | 24.0% | 8.43 | 66% |
| **AF_PACKET** | 729,203 | 27.1% | 8.41 | 74% |
| **AF_XDP Copy** | 1,000,015 | **0%** | **11.54** | **41%** |
| **AF_XDP Zero-Copy** | 1,000,010 | **0%** | **11.54** | **47%** |

### Key Findings

1. **AF_XDP achieves line rate** (1M pps) with 0% loss
2. **AF_XDP uses 35-45% less CPU** than Socket/AF_PACKET
3. **Socket/AF_PACKET saturate at ~750K pps** with significant loss
4. **Copy vs Zero-Copy**: Nearly identical performance on gVNIC

## Results: All Rates

### 100K pps (Under Saturation)

| Backend | PPS | Loss | Gb/s |
|---------|-----|------|------|
| Socket | 99,002 | 0.008% | 1.11 |
| AF_PACKET | 99,990 | 0% | 1.15 |
| AF_XDP Copy | 100,002 | 0% | 1.15 |
| AF_XDP Zero-Copy | 100,001 | 0% | 1.15 |

### 500K pps (Near Saturation)

| Backend | PPS | Loss | Gb/s |
|---------|-----|------|------|
| Socket | 495,045 | 0.0006% | 5.55 |
| AF_PACKET | 499,994 | 0% | 5.77 |
| AF_XDP Copy | 500,003 | 0% | 5.77 |
| AF_XDP Zero-Copy | 500,002 | 0% | 5.77 |

### 1M pps (At Saturation)

| Backend | PPS | Loss | Gb/s | CPU |
|---------|-----|------|------|-----|
| Socket | 826,167 | 16.6% | 9.25 | 66% |
| AF_PACKET | 765,197 | 23.5% | 8.83 | 74% |
| AF_XDP Copy | 1,000,005 | 0% | 11.54 | 41% |
| AF_XDP Zero-Copy | 1,000,005 | 0% | 11.54 | 47% |

### 2M pps (Over Saturation)

| Backend | PPS | Loss | Gb/s |
|---------|-----|------|------|
| Socket | 1,053,844 | 47.3% | 11.80 |
| AF_PACKET | 762,226 | 61.9% | 8.79 |
| AF_XDP Copy | 1,792,127 | 10.4% | 20.67 |
| AF_XDP Zero-Copy | 1,774,134 | 11.3% | 20.47 |

## Saturation Points (Zero Loss)

| Backend | Max PPS | Max Gb/s | vs AF_XDP |
|---------|---------|----------|-----------|
| Socket | ~500K | ~5.6 | 2.0x slower |
| AF_PACKET | ~500K | ~5.8 | 2.0x slower |
| AF_XDP Copy | ~1.0M | ~11.5 | baseline |
| AF_XDP Zero-Copy | ~1.0M | ~11.5 | baseline |

## CPU Efficiency at 1M pps

| Backend | CPU % | Efficiency |
|---------|-------|------------|
| Socket | 66% | Baseline |
| AF_PACKET | 74% | 12% worse |
| AF_XDP Copy | 41% | **38% better** |
| AF_XDP Zero-Copy | 47% | **29% better** |

## Limitations

1. **gVNIC XDP Queue Limit**: Max 2 queues for XDP (half of 4 max)
2. **Virtualized NIC**: No true zero-copy benefit on gVNIC
3. **Single Core**: All tests pinned to 1 CPU core

## References

- [AF_XDP Kernel Documentation](https://www.kernel.org/doc/html/latest/networking/af_xdp.html)
- [XDP Paper (LPC 2018)](http://vger.kernel.org/lpc_net2018_talks/lpc18_paper_af_xdp_perf-v2.pdf)
- [Cloudflare L4Drop](https://blog.cloudflare.com/l4drop-xdp-ebpf-based-ddos-mitigations/)
