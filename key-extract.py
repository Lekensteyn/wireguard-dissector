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
# (if PSK is in use: mix_key)
# wgkey5: consume_resp  initiator=(I) responder=(R)                 ->initiator+responder ID
# wgkey4: index_ht      mask=1 id=(I)                               ->receiver ID
# wgkey2: blake2s_hmac  inlen=32,1,33   mix_key -> kdf(#data=32)    just update ChainedKey
# wgkey2: blake2s_hmac  inlen=32,1,33   mix_key -> kdf(#data=32)    ->key2 for empty
# -- (not under HS lock):
# wgkey2: blake2s_hmac  inlen=0,1,33    derive_secrets -> kdf(0)    data="", ->key1,2 for two traffic keys
# -- TRANSPORT (need Receiver ID)

# Guessed sequence (Responder perspective):
# TODO
# wgkey2: blake2s_hmac  inlen=32,1,33   mix_key -> kdf(#data=32)    just update ChainedKey
# wgkey2: blake2s_hmac  inlen=32,1,33   mix_key -> kdf(#data=32)    ->key2 for empty
# wgkey1: encrypt       src_len=0       handshake_encrypt           data=""
# -- (not under HS lock):
# wgkey2: blake2s_hmac  inlen=0,1,33    derive_secrets -> kdf(0)    data="", ->key1,2 for two traffic keys

# Not so reliable values (could be intermixed with other messages).
# BUT can be used to link receiver ID to sender ID (and vice versa)
# noise_handshake_consume_response(struct message_handshake_response *src, ...)
# noise_handshake_create_response(struct message_handshake_response *dst, ...)
# src->sender_index     +4($di)
# src->receiver_index   +8($di)

# Identifiers produced by kprobes
TYPE_ID_INSERT          = "wgkey0"
TYPE_HANDSHAKE_ENCRYPT  = "wgkey1"
TYPE_BLAKE2S_HMAC       = "wgkey2"
TYPE_COOKIE             = "wgkey3"
TYPE_I_RESPONDER_ID     = "wgkey4"
TYPE_I_IDS              = "wgkey5"
TYPE_R_IDS              = "wgkey6"

# Size of the input data for AEAD (src_len)
SIZE_STATIC = 32
SIZE_TIMESTAMP = 12
SIZE_EMPTY = 0

# Magic constant used by the hashtables implementation
INDEX_HASHTABLE_HANDSHAKE = 1

# Identifiers for output
KEY_STATIC      = "STATIC"
KEY_TIMESTAMP   = "TIMESTAMP"
KEY_EMPTY       = "EMPTY"
KEY_TRAFFIC     = "TRAFFIC"


def parse_args_dict(text):
    """Parses arguments from text into mapping from the key to a number."""
    r = {}
    for val in text.split():
        k, v = val.split("=")
        r[k] = int(v, 0)
    return r


def parse_lines(f):
    pattern = r'.*: (?P<key>wgkey[0-6]): \([^)]+\) (?P<args>.+)'
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

    # Maps initiator ID to responder ID (and vice versa)
    map_ir, map_ri = {}, {}
    # Remember updates to the KDF such that the output can be calculated later.
    kdf = Kdf()

    # Collected keys for the initiator side
    static_key, timestamp_key = None, None

    # Context for response processing
    responder_id = None
    response_kdf_seen = 0

    for what, args in parse_lines(sys.stdin):
        # Chainkey is learned through handling handshake_encrypt for producing "empty"
        final_chainkey, empty_key = None, None

        # Debug
        #print(what, args)

        if what == TYPE_BLAKE2S_HMAC:
            kdf.update(args["inlen"], args["key"])
            # Heuristics: after learning Responder ID and one KDF, the next KDF
            # results in the final chainkey and and empty_key
            if responder_id is not None and args["inlen"] == 1 + 32:
                response_kdf_seen += 1
                if response_kdf_seen == 2:
                    final_chainkey, empty_key = kdf.keys()

        if what == TYPE_HANDSHAKE_ENCRYPT:
            src_len = args["src_len"]
            # The KDF that generates the AEAD key takes the DH shared secret as
            # input data (which is 32 bytes).
            if kdf.input_length != 32:
                _logger.warn("Unexpected KDF input size %d for encryption\n",
                        kdf.input_length)
                continue
            if src_len == SIZE_STATIC:
                static_key = kdf.key()
            elif src_len == SIZE_TIMESTAMP:
                timestamp_key = kdf.key()
            elif src_len == SIZE_EMPTY:
                # TODO is this for responder only?
                # This chained secret is used as key for deriving traffic keys
                #final_chainkey, empty_key = kdf.keys()
                _logger.warn("Unimplemented handshake response create")
            else:
                _logger.warn("Unhandled handshake_encrypt(src_len=%d)", src_len)

        if final_chainkey:
            # Chainkey was learned above while deriving secrets for encrypting "empty"
            if responder_id is None:
                _logger.warn("Unknown Responder ID, cannot derive traffic secrets")
                continue
            initiator_id = map_ri[responder_id]
            # Note: RID was previously mapped via IID in TYPE_I_RESPONDER_ID
            print_key(KEY_EMPTY, responder_id, empty_key)
            # Expand traffic keys for decryption
            initiator_key, responder_key = Kdf.hkdf_expand(final_chainkey)
            print_key(KEY_TRAFFIC, initiator_id, initiator_key)
            print_key(KEY_TRAFFIC, responder_id, responder_key)
            response_kdf_seen = 0
            responder_id = None

        # End of constructing an initiation message
        if what == TYPE_ID_INSERT:
            initiator_id = args["id"]
            print_key(KEY_STATIC, initiator_id, static_key)
            print_key(KEY_TIMESTAMP, initiator_id, timestamp_key)
            static_key, timestamp_key = None, None

        # Begin of received response processing
        if what == TYPE_I_RESPONDER_ID:
            if args["mask"] != INDEX_HASHTABLE_HANDSHAKE:
                # Skip other users of index_hashtable_lookup()
                continue
            initiator_id = args["id"]
            response_kdf_seen = 0
            responder_id = map_ir.get(initiator_id)
            if responder_id is None:
                _logger.warn("Unknown Responder ID for response to 0x%08x", initiator_id)

        if what in (TYPE_I_IDS, TYPE_R_IDS):
            iid, rid = args["initiator"], args["responder"]
            map_ir[iid] = rid
            map_ri[rid] = iid


if __name__ == '__main__':
    main()
