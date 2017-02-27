#!/usr/bin/env python
# Post-processes traces and produce a suitable keylog file.
# Requires Python 3.4 or newer (due to HMAC with Blake2s)
import argparse
import hashlib
import hmac
import logging
import re
import struct
import sys

_logger = logging.getLogger(__name__)

# mix_key(dst_key, chaining_key, src, src_len)
# -> kdf(dst1, dst2, data, ..., data_len=src_len, ..., chaining_key)
#    -> blake2s_hmac(SEC, in=data, key=chaining_key, ..., inlen=data_len, ...)
#       blake2s_hmac(..., in="\1", key=SEC, ...)    <-- Log this SEC, derive       key1,key2
# handshake_encrypt(dst, src, src_len, key, ...)
# -> chacha20poly1305_encrypt(..., key)
# derive_secrets(respondDecryptKeys, sendDecryptKeys)

# INDEX_HASHTABLE_HANDSHAKE = 1
# index_hashtable_lookup(..., INDEX_HASHTABLE_HANDSHAKE, receiver_index)
# there you go! receiver index in RESPONSE PROC, under handshake lock
#
# (if PSK is in use:
#  handshake_init -> kdf(32)
#  mix_key -> kdf(32)
# )
# Observed sequence (Initiator perspective):
# -- INIT (need Sender ID) under handshake lock
# wgkey2: blake2s_hmac  inlen=32,1,33   mix_key -> kdf(#data=32)    ->key2 for static
# wgkey1: encrypt       src_len=32      handshake_encrypt           data=static public key for initiator
# wgkey2: blake2s_hmac  inlen=32,1,33   mix_key -> kdf(#data=32)    ->key2 for timestamp
# wgkey1: encrypt       src_len=12      handshake_encrypt           data=timestamp
# wgkey0: ht_insert     id=(I)                                      ->sender ID
# -- RESPONSE PROC (need Sender/Receiver ID, depending on side) under handshake lock
# wgkey5: consume_resp  initiator=(I) responder=(R)                 ->initiator+responder ID
# (if PSK is in use: mix_key)
# wgkey2: blake2s_hmac  inlen=32,1,33   mix_key -> kdf(#data=32)    just update ChainedKey
# wgkey2: blake2s_hmac  inlen=32,1,33   mix_key -> kdf(#data=32)    ->key2 for empty
# wgkey7: decrypt       src_len=0       handshake_decrypt           data="" (empty)
# -- (not under HS lock):
# wgkey2: blake2s_hmac  inlen=0,1,33    derive_secrets -> kdf(0)    data="", ->key1,2 for two traffic keys
# -- TRANSPORT (need Receiver ID)

# Observed sequence (Responder perspective):
# -- INIT PROC *not* under handshake lock (only static_identity lock)
# wgkey6: consume_init  initiator=(I)                               ->initiator ID
# (if PSK is in use: mix_key)
# wgkey2: blake2s_hmac  inlen=32,1,33   mix_key -> kdf(#data=32)    ->key2 for static
# wgkey7: decrypt       src_len=32+16   handshake_decrypt           data=encrypted static
# wgkey2: blake2s_hmac  inlen=32,1,33   mix_key -> kdf(#data=32)    ->key2 for timestamp
# wgkey7: decrypt       src_len=12+16   handshake_decrypt           data=encrypted timestamp
# -- RESPONSE under handshake lock
# (if PSK is in use: mix_key)
# wgkey2: blake2s_hmac  inlen=32,1,33   mix_key -> kdf(#data=32)    just update ChainedKey
# wgkey2: blake2s_hmac  inlen=32,1,33   mix_key -> kdf(#data=32)    ->key2 for empty
# wgkey1: encrypt       src_len=0       handshake_encrypt           data="" (empty)
# wgkey0: ht_insert     id=(R)                                      ->sender ID
# -- (not under HS lock):
# wgkey2: blake2s_hmac  inlen=0,1,33    derive_secrets -> kdf(0)    data="", ->key1,2 for two traffic keys

# Note: with multiple handshakes, there can still be a race in output... so locking is useless
# noise_handshake_consume_initiation (no lookup otherwise...). Can be racy!
# src->sender_index     +4($di)
#
# Not so reliable values (could be intermixed with other messages).
# BUT can be used to link receiver ID to sender ID (and vice versa)
# noise_handshake_consume_response(struct message_handshake_response *src, ...)
# src->sender_index     +4($di)
# src->receiver_index   +8($di)


# KDF output and encrypt/decrypt keys have common information.
# Can obtain the following keys (triggered sender I/R between parentheses):
# (create_initiation)
# v- encrypt(src_len=32)        static (I)
# v- encrypt(src_len=12)        timestamp (I)
# ht_insert                     returns Sender ID (IID)
# [can clear static, timestamp, IID]
#
# consume_response(src={responder_id, initiator_id})
#    v- kdf                     traffic secrets (IID+RID from src)
# ^- decrypt(src_len=0+16)      empty (I)
# [can clear empty, RID, IID]
#
# consume_initiation(src={initiator_id})
# ^- decrypt(src_len=32+16)     static (R)
# ^- decrypt(src_len=12+16)     timestamp (R)
# [can clear static, timestamp, but not IID]
# (create_response)
#    v- kdf                     traffic secrets (RID from next ht_insert, IID from consume_initiation)
# v- encrypt(src_len=0)         empty (R)
# ht_insert                     returns Sender ID (RID)
# [can clear empty, IID, RID]
#
# NOTE: last kdf before encrypt/decrypt(src_len=0) is traffic secret
# NOTE: encrypt provides information about side, ht_insert returns Sender ID


# Identifiers produced by kprobes
TYPE_ID_INSERT          = "wgkey0"
TYPE_HANDSHAKE_ENCRYPT  = "wgkey1"
TYPE_HANDSHAKE_DECRYPT  = "wgkey7"
TYPE_BLAKE2S_HMAC       = "wgkey2"
TYPE_COOKIE             = "wgkey3"
TYPE_CONSUME_INITIATION = "wgkey6"
TYPE_CONSUME_RESPONSE   = "wgkey5"

# Size of the input data for AEAD (src_len)
SIZE_STATIC = 32
SIZE_TIMESTAMP = 12
SIZE_EMPTY = 0

# Magic constant used by the hashtables implementation
INDEX_HASHTABLE_HANDSHAKE = 1

# Identifiers for output
KEY_STATIC      = "STAT"
KEY_TIMESTAMP   = "TIME"
KEY_EMPTY       = "EMPT"
KEY_TRAFFIC     = "DATA"


def parse_args_dict(text):
    """Parses arguments from text into mapping from the key to a number."""
    r = {}
    for val in text.split():
        k, v = val.split("=")
        r[k] = int(v, 0)
    return r


def parse_lines(f):
    pattern = r'.*: (?P<key>wgkey[0-7]): \([^)]+\) (?P<args>.+)'
    for line in f:
        line = line.strip()
        m = re.match(pattern, line)
        if not m:
            _logger.debug("Skipping %s", line)
            continue
        _logger.debug("Matched %s", m.groupdict())
        args = parse_args_dict(m.group("args"))
        if 'key1' in args:
            # Fixup the key, replacing integers key1..key4 by bytes "key"
            args['key'] = struct.pack('<QQQQ',
                    args['key1'], args['key2'], args['key3'], args['key4'])
            for i in range(1, 4 + 1):
                del args['key%d' % i]
        yield m.group("key"), args


def blake2s_hmac(key, msg):
    return hmac.new(key, msg=msg, digestmod=hashlib.blake2s).digest()


class Kdf(object):
    def __init__(self):
        self.input_length = None
        self._keys = None

    def update(self, inlen, key):
        if inlen == 1:
            # Second: key is PRK, so now we can calculate the HKDF output.
            self._keys = Kdf.hkdf_expand(key)
        elif inlen == 1 + 32:
            # Third: T(2) = HMAC(PRK, T(1) || 0x02)
            if not self._keys:
                # This can happen if the output is truncated at the beginning.
                _logger.info("Previous round missing, deriving keys now")
                self._keys = Kdf.hkdf_expand(key)
        else:
            # First: PRK = HMAC(key, input) where key is the chaining key in WG
            self.input_length = inlen
            self._keys = None

    def keys(self):
        """
        Returns the derived key material, clearing the state for a new iteration.
        """
        if not self._keys:
            _logger.warn("Derived key is not known")
            return None, None
        keys = self._keys
        self._keys = None
        return keys

    def key(self, n=1):
        """Obtain one half of the key (if any) and clears the state."""
        keys = self.keys()
        return keys[n]

    @staticmethod
    def hkdf_expand(prk):
        """
        Takes the pseudorandom key PRK and expands it to 2 × 32 bytes using Blake2s.
        """
        # T(1) = HMAC(PRK, 0x01)
        # T(2) = HMAC(PRK, T(1) || 0x02)
        t1 = blake2s_hmac(prk, b'\1')
        t2 = blake2s_hmac(prk, t1 + b'\2')
        return t1, t2


def print_key(what, sender_id, key):
    # Note: KEY_TRAFFIC is linked by Receiver ID (not Sender ID)
    if sender_id is None:
        _logger.warn("Unknown Sender ID for %s\n", what)
        return
    if not key:
        _logger.warn("Unknown key for %s with ID 0x%08x\n", what, sender_id)
        return
    print("%s 0x%08x %s" % (what, sender_id, key.hex()))


parser = argparse.ArgumentParser()
parser.add_argument("--debug", action="store_true",
    help="Increase logging verbosity")


def main():
    args = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
        format='%(asctime)s - %(message)s')

    # Remember updates to the KDF such that the output can be calculated later.
    kdf = Kdf()
    # Whether the current context is an Initiator or Responder
    context_is_responder = None

    # Collected keys for both sides (at Initiator or Responder side)
    static_key_I, timestamp_key_I = None, None
    empty_key_R = None
    traffic_keys_I, traffic_keys_R = None, None

    # Context for received message processing (at Initiator or Responder side)
    initiator_id_R = None
    responder_id_I, initiator_id_I = None, None

    for what, args in parse_lines(sys.stdin):
        # The decryption keys for the receiving side (if known at this point).
        traffic_receiver_id_I, traffic_receiver_id_R = None, None

        # Debug
        #print(what, args)

        if what == TYPE_BLAKE2S_HMAC:
            kdf.update(args["inlen"], args["key"])

        if what == TYPE_HANDSHAKE_ENCRYPT:
            plain_len, key = args["src_len"], args["key"]
            if plain_len == SIZE_STATIC:
                static_key_I = key
            elif plain_len == SIZE_TIMESTAMP:
                timestamp_key_I = key
                # Remember context for linking static+timestamp to Initiator.
                context_is_responder = False
            elif plain_len == SIZE_EMPTY:
                empty_key_R = key
                # Remember context for traffic secrets and linking empty to R.
                context_is_responder = True
            else:
                _logger.warn("Unhandled handshake_encrypt(src_len=%d)", args["src_len"])

        if what == TYPE_HANDSHAKE_DECRYPT:
            plain_len, key = args["src_len"] - 16, args["key"]
            if plain_len == SIZE_STATIC:
                print_key(KEY_STATIC, initiator_id_R, key)
            elif plain_len == SIZE_TIMESTAMP:
                print_key(KEY_TIMESTAMP, initiator_id_R, key)
            elif plain_len == SIZE_EMPTY:
                # Chain Key for traffic secrets should be available now.
                traffic_receiver_id_R, traffic_receiver_id_I = responder_id_I, initiator_id_I
                print_key(KEY_EMPTY, responder_id_I, key)
                initiator_id_I, responder_id_I = None, None
            else:
                _logger.warn("Unhandled handshake_decrypt(src_len=%d)", args["src_len"])

        # Begin of received response processing by Initiator
        if what == TYPE_CONSUME_RESPONSE:
            # Remember for traffic secrets (KDF) and empty decryption context.
            initiator_id_I, responder_id_I = args["initiator"], args["responder"]

        # Begin of received initiation processing by Responder
        if what == TYPE_CONSUME_INITIATION:
            # Remember for linking all (traffic) secrets at responder side.
            initiator_id_R = args["initiator"]

        # End of constructing an initiation message
        if what == TYPE_ID_INSERT:
            sender_id = args["id"]
            if context_is_responder is False:
                # Initiator side
                print_key(KEY_STATIC, sender_id, static_key_I)
                print_key(KEY_TIMESTAMP, sender_id, timestamp_key_I)
                static_key_I, timestamp_key_I = None, None
            elif context_is_responder is True:
                # Responder side
                print_key(KEY_EMPTY, sender_id, empty_key_R)
                # Chain Key for traffic secrets should be available now.
                traffic_receiver_id_R, traffic_receiver_id_I = sender_id, initiator_id_R
                empty_key_R, initiator_id_R = None, None
            else:
                _logger.warn("Unknown side for Sender ID 0x%08x", sender_id)
            context_is_responder = None

        # If traffic secret can be derived now, do so
        if traffic_receiver_id_R is not None:
            assert traffic_receiver_id_I is not None
            final_chainkey = kdf.key(0)
            prk = blake2s_hmac(final_chainkey, b'')
            receive_key_R, receive_key_I = Kdf.hkdf_expand(prk)
            print_key(KEY_TRAFFIC, traffic_receiver_id_R, receive_key_R)
            print_key(KEY_TRAFFIC, traffic_receiver_id_I, receive_key_I)


if __name__ == '__main__':
    main()
