#!/bin/bash
set -euo pipefail

if [ "$#" -ne 7 ]; then
    echo "usage: $0 <iface> <dst-mac> <src-ip> <dst-ip> <payload-bytes> <pps> <seconds>" >&2
    exit 1
fi

iface=$1
dst_mac=$2
src_ip=$3
dst_ip=$4
payload_bytes=$5
pps=$6
seconds=$7
frame_bytes=$((payload_bytes + 42))
packet_count=$((pps * seconds))

if [ "$frame_bytes" -lt 60 ] || [ "$frame_bytes" -gt 1514 ]; then
    echo "payload must produce a 60-1514 byte Ethernet frame" >&2
    exit 1
fi

modprobe pktgen

pgset() {
    local file=$1
    local value=$2
    echo "$value" > "$file"
    local result
    result=$(cat "$file")
    if [[ "$result" == *"Result: FAIL"* ]]; then
        printf '%s\n' "$result" >&2
        exit 1
    fi
}

pgset /proc/net/pktgen/pgctrl "reset"
pgset /proc/net/pktgen/kpktgend_0 "rem_device_all"
pgset /proc/net/pktgen/kpktgend_0 "add_device ${iface}@0"

device=/proc/net/pktgen/${iface}@0
pgset "$device" "count ${packet_count}"
pgset "$device" "pkt_size ${frame_bytes}"
pgset "$device" "dst ${dst_ip}"
pgset "$device" "src_min ${src_ip}"
pgset "$device" "dst_mac ${dst_mac}"
pgset "$device" "udp_dst_min 9100"
pgset "$device" "udp_dst_max 9100"
pgset "$device" "udp_src_min 10000"
pgset "$device" "udp_src_max 10063"
pgset "$device" "flag UDPSRC_RND"
pgset "$device" "ratep ${pps}"
pgset "$device" "queue_map_min 0"
pgset "$device" "queue_map_max 0"

echo "Sending ${payload_bytes}-byte UDP payloads at ${pps} pps for ${seconds}s"
echo "start" > /proc/net/pktgen/pgctrl
cat "$device"
