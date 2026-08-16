#!/bin/bash
# CPU monitoring wrapper for falcon-rxbench
# Usage: ./run_with_cpu.sh <backend> <target> <seconds> <expected_packets> <cpu_id>

BACKEND=$1
TARGET=$2
SECONDS=$3
EXPECTED=$4
CPU_ID=${5:-0}

# Get initial CPU stats
read_cpu() {
    grep "cpu$CPU_ID " /proc/stat | awk '{print $2+$3+$4+$5+$6+$7+$8}'
}
read_cpu_idle() {
    grep "cpu$CPU_ID " /proc/stat | awk '{print $5+$6}'
}

CPU_START=$(read_cpu)
CPU_IDLE_START=$(read_cpu_idle)

# Run benchmark
sudo taskset -c $CPU_ID /home/yashwanth8099/Falcon/build/falcon-rxbench $BACKEND $TARGET $SECONDS $EXPECTED

# Get final CPU stats
CPU_END=$(read_cpu)
CPU_IDLE_END=$(read_cpu_idle)

# Calculate CPU usage
CPU_DELTA=$((CPU_END - CPU_START))
IDLE_DELTA=$((CPU_IDLE_END - CPU_IDLE_START))
if [ $CPU_DELTA -gt 0 ]; then
    CPU_PERCENT=$((100 * (CPU_DELTA - IDLE_DELTA) / CPU_DELTA))
else
    CPU_PERCENT=0
fi

echo "cpu_percent,$CPU_PERCENT"
