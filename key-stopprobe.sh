#!/bin/sh
set -x -e

# Disable old kprobes first (ignore errors about non-existence)
echo 0 > /sys/kernel/debug/tracing/events/kprobes/enable || :
# Remove kprobes
echo > /sys/kernel/debug/tracing/kprobe_events
# Clear trace log
echo > /sys/kernel/debug/tracing/trace

# Example to disable kprobes selectively:
#echo 0 | tee /sys/kernel/debug/tracing/events/kprobes/wgkey*/enable &>/dev/null || :
#grep -o '^[rp]:wgkey[0-9]' /sys/kernel/debug/tracing/events/kprobe_events |
#    sed 's/[rp]/-/' >> /sys/kernel/debug/tracing/events/kprobe_events

echo DONE
