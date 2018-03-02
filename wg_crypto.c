/**
 * Cryptographic routines for calculating decryption keys for WireGuard.
 * Copyright (C) 2018 Peter Wu <peter@lekensteyn.nl>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <string.h>
#include "wg_crypto.h"
#include <sodium.h>

static gboolean
decode_base64_key(wg_key_t *out, const char *str)
{
    gsize out_len;
    gchar tmp[45];

    if (strlen(str)+1 != sizeof(tmp)) {
        return FALSE;
    }
    memcpy(tmp, str, sizeof(tmp));
    g_base64_decode_inplace(tmp, &out_len);
    if (out_len != sizeof(wg_key_t)) {
        return FALSE;
    }
    memcpy((char *)out, tmp, sizeof(wg_key_t));
    return TRUE;
}

static void
priv_to_pub(wg_key_t *priv, wg_key_t *pub)
{
    crypto_scalarmult_base((guchar *)pub, (guchar *)priv);
}

gboolean
wg_process_keys(
    wg_keys_t  *keys_out,
    const char *sender_static_private_str,
    const char *receiver_static_public_str,
    const char *sender_ephemeral_private_str,
    const char *psk_str
)
{
    memset(keys_out, 0, sizeof(wg_keys_t));
    if (!decode_base64_key(&keys_out->sender_static.private_key, sender_static_private_str) ||
        !decode_base64_key(&keys_out->sender_ephemeral.private_key, sender_ephemeral_private_str) ||
        !decode_base64_key(&keys_out->receiver_static_public, receiver_static_public_str) ||
        !decode_base64_key(&keys_out->psk, psk_str)) {
        return FALSE;
    }
    priv_to_pub(&keys_out->sender_static.private_key, &keys_out->sender_static.public_key);
    priv_to_pub(&keys_out->sender_ephemeral.private_key, &keys_out->sender_ephemeral.public_key);
}

/**
 * Find the correct keys from the initiation message msg1 as follows:
 * 1. Assume every keys "k" from the keys set is valid.
 * 2. For all keys "k" which have a matching msg.ephemeral, keys "k" is likely
 *    from the initiator (but in a malicious case it does not have to). Group
 *    keys by k.remote_static_public (and for the malicious case, also group by
 *    k.local_static_public).
 * 3. For all keys "k" which have no matching msg.ephemeral, either there is no
 *    valid "k" available or the keys "k" are from the responder. Group keys by
 *    k.local_static_public.
 * 4. Prioritize keys "k" which have a matching msg.ephemeral with
 *    k.sender_static_public.
 * 5. Test that msg.mac1 can be validated by one of the static public keys.
 * 6. The remaining set of keys must be trial decrypted. If all goes well, there
 *    is a single key such that decrypt(msg.static) = Spub_r.
 *    "Spub_r = msg.receiver_static_public" if "k" belongs to initiator and
 *    "Spub_r = msg.sender_static_public" if "k" belongs to the responder).
 * 7. Remember association "a = (msg1.sender, ChainedKey, ChainedHash, k, kType)".
 *    kType is Initiator or Responder. Note that if for some malicious reason
 *    the static and ephemeral keys are exactly the same, the type choice does
 *    not matter (both are equally valid).
 *    For convenience set pointers can also be set such that following steps can
 *    refer to k.Spub_r and k.Spub_i rather than checking the kType (which then
 *    is no longer necessary).
 *
 * For the responder message msg2, match msg1 as follows with msg2:
 * 1. Find associations with "msg2.receiver = msg1.sender".
 * 2. Group associations by k.Spub_i.
 * 3. Test that msg2.mac1 can be validated by Spub_i
 * 4. Trial decrypt, if all goes well, one msg1 (with its crypto context) should
 *    be returned.
 * 5. Derive transport keys.
 * 6. Keys "k" are no longer needed, they could be erased to save memory.
 *    (Keep it when malicious traffic with key reuse needs to be considered.)
 *
 * For validation reasons, remember for both initiation and response which
 * Spub_i and Spub_r were used (display it in the proto tree).
 */

gboolean
wg_process_initiation(
    const guchar       *msg,
    guint               msg_len,
    const wg_keys_t    *keys,
    wg_key_t          **static_public_i,
    guchar            **timestamp
)
{
    // Inputs:
    //  Spub_r, Spub_i, Spriv_i, Epriv_i    if kType = I
    //  Spub_r, Spub_i, Spriv_r             if kType = R
    //
    // c = Hash(CONSTRUCTION)
    // h = Hash(c || msg.sender)
    // h = Hash(h || Spub_r)
    // c = KDF1(c, msg.ephemeral)
    // h = Hash(h || msg.ephemeral)
    //  dh1 = DH(Epriv_i, Spub_r)           if kType = I
    //  dh1 = DH(Spriv_r, msg.ephemeral)    if kType = R
    // (c, k) = KDF2(c, dh1)
    // Spub_i = AEAD-Decrypt(k, 0, msg.static, h)
    //  -- now check that Spub_i matches in keys "k"
    // h = Hash(h || msg.static)
    //  dh2 = DH(Spriv_i, Spub_r)           if kType = I
    //  dh2 = DH(Spriv_r, Spub_i)           if kType = R
    // (c, k) = KDF2(c, dh2)
    // timestamp = AEAD-Decrypt(k, 0, msg.timestamp, h)
    // h = Hash(h || msg.timestamp)
}
