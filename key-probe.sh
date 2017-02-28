#!/bin/bash
# Enable extraction of WireGuard keys
# Copyright (C) 2017 Peter Wu <peter@lekensteyn.nl>
#
# This work is licensed under the terms of GPLv2 (or any later version).
#
# wgkey0: sender ID                                 id=%x
# wgkey1: key for static/timestamp/empty (encr)     src_len=%d key1..4=%x aad1..4=%x
# wgkey7: key for static/timestamp/empty (decr)     src_len=%d key1..4=%x aad1..4=%x
# wgkey2: traffic secret base key (need inlen=0)    inlen=%d key1..4=%x
# wgkey3: cookie key                                key1..4=%x
# wgkey5: link sender+receiver (initiator consume)  initiator=%x responder=%x
# wgkey6: link sender (responder consume)           initiator=%x
# NOTE: key1..key4 are affected by endianess (little endian on x86-64).
#
# See also Documentation/trace/kprobetrace.txt
# Registers for args on x86-64: di si dx cx r8 r9
# Arguments 7, 8, etc. are on stack, +8 +0x10 etc. (+0 is return address)

set -x -e

# If wireguard is a built-in, there is no kernel module.
[ -e /sys/module/wireguard ] && MOD=wireguard: || MOD=

# Disable old kprobes first
echo 0 | tee /sys/kernel/debug/tracing/events/kprobes/wgkey*/enable &>/dev/null || :

# Find Sender ID
# (Sender: Initiator; Receiver: Responder, Transport, Cookie)
# noise_handshake_create_initiation / noise_handshake_create_response
# -> index_hashtable_insert%return:
#   Initiator Sender ID (noise_handshake_create_initiation)
#   Responder Sender ID (noise_handshake_create_response)
echo > /sys/kernel/debug/tracing/kprobe_events \
    'r:wgkey0 '$MOD'index_hashtable_insert id=$retval:x32'

# Find link between Initiator and Responder IDs
# noise_handshake_consume_response(msg, ...)
# noise_handshake_consume_initiation(msg, ...)
echo >> /sys/kernel/debug/tracing/kprobe_events \
    'p:wgkey5 '$MOD'noise_handshake_consume_response initiator=+8(%di):x32 responder=+4(%di):x32'
echo >> /sys/kernel/debug/tracing/kprobe_events \
    'p:wgkey6 '$MOD'noise_handshake_consume_initiation initiator=+4(%di):x32'


# Set new kprobe
# noise_handshake_create_initiation / noise_handshake_create_response
# -> handshake_encrypt
#    -> chacha20poly1305_encrypt
# src_len is the length of the input data to be encrypted:
#  32 for responder secret  (noise_handshake_create_initiation)
#  12 for timestamp         (noise_handshake_create_initiation)
#  0  for empty             (noise_handshake_create_response)
# Key length for ChaCha20-Poly1305 is always 32 bytes.
# arg4 (%cx) is aad, arg7 (+8($stack)) is key
keyarg='key1=+0(+8($stack)) key2=+8(+8($stack)) key3=+0x10(+8($stack)) key4=+0x18(+8($stack))'
aadarg='aad1=+0(%cx) aad2=+8(%cx) aad3=+0x10(%cx) aad4=+0x18(%cx)'
echo >> /sys/kernel/debug/tracing/kprobe_events \
    "p:wgkey1 ${MOD}chacha20poly1305_encrypt src_len=%dx:u64 $keyarg $aadarg"

# noise_handshake_consume_initiation / noise_handshake_consume_response
# -> handshake_decrypt
#    -> chacha20poly1305_decrypt
# arg4 (%cx) is aad, arg7 (+8($stack)) is key
echo >> /sys/kernel/debug/tracing/kprobe_events \
    "p:wgkey7 ${MOD}chacha20poly1305_decrypt src_len=%dx:u64 $keyarg $aadarg"

# Grab keys for KDF and remember input data length for context.
# noise_handshake_begin_session
# -> derive_keys(sendkeys, recvkeys, chaining_key)
#    -> kdf(sendkeys, recvkeys, data="", chaining_key)
#       -> blake2s_hmac(out, in="", key[32], outlen=32, inlen=0, keylen=32)
#       -> blake2s_hmac(sendkeys, in=        "\1", key, outlen=32, inlen=1, keylen=32)
#       -> blake2s_hmac(recvkeys, in=sendkeys"\2", key, outlen=32, inlen=33, keylen=32)
# Note: HMAC output length is indeed same as ChaCha20-Poly1305 key length (32 bytes)
#
# blake2s_hmac is only called three times with inlen as distinguisher!
# Unfortunately kretprobes cannot be used to access argument registers (out).
# Alternative idea: capture input 'key' and derive others from key with inlen=1
echo >> /sys/kernel/debug/tracing/kprobe_events \
    'p:wgkey2 '$MOD'blake2s_hmac inlen=%r8:u64 key1=+0(%dx) key2=+8(%dx) key3=+0x10(%dx) key4=+0x18(%dx)'

# TODO grab Cookie secret XXX untested
# cookie_message_create
# -> xchacha20poly1305_encrypt
# arg4 (%cx) is aad, arg6 (%r9) is nonce, arg7 (+8($stack)) is key
#echo >> /sys/kernel/debug/tracing/kprobe_events \
#    'p:wgkey3 '$MOD'xchacha20poly1305_encrypt TODO'

echo 1 | tee /sys/kernel/debug/tracing/events/kprobes/wgkey*/enable >/dev/null

# Wipe old traces
echo > /sys/kernel/debug/tracing/trace

# Show command to read trace
cat <<EOF
cat /sys/kernel/debug/tracing/trace
# read indefinitely and clear buffer
cat /sys/kernel/debug/tracing/trace_pipe
EOF
