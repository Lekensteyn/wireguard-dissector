/**
 * Cryptographic routines for calculating decryption keys for WireGuard.
 * Copyright (C) 2018 Peter Wu <peter@lekensteyn.nl>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <string.h>
#include "wg_crypto.h"
#include <sodium.h>
#include "wsgcrypt_compat.h" /* for HKDF */
#include <gcrypt.h>

/** Wire serialization of initiation message. */
typedef struct {
    guchar  type;
    guchar  reserved[3];
    guchar  sender[4];
    guchar  ephemeral[32];
    guchar  static_public[32+16];
    guchar  timestamp[12+16];
    guchar  mac1[16];
    guchar  mac2[16];
} wg_initiation_message_t;
G_STATIC_ASSERT(sizeof(wg_initiation_message_t) == 148);

#define WG_RESPONSE_LENGTH              92

/** Hash(CONSTRUCTION), initialized by wg_decrypt_init. */
static wg_hash_t hash_of_construction;

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
priv_to_pub(const wg_key_t *priv, wg_key_t *pub)
{
    crypto_scalarmult_base((guchar *)pub, (const guchar *)priv);
}

static void
dh_x25519(wg_key_t *shared_secret, const wg_key_t *priv, const wg_key_t *pub)
{
    int r;
    r = crypto_scalarmult((guchar *)shared_secret, (const guchar *)priv, (const guchar *)pub);
    /* Assume private key is valid. */
    g_assert(r == 0);
}

gboolean
wg_decrypt_init(void)
{
    if (gcry_md_test_algo(GCRY_MD_BLAKE2S_128) != 0 ||
        gcry_md_test_algo(GCRY_MD_BLAKE2S_256) != 0) {
        return FALSE;
    }
    static const char construction[] = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
    gcry_md_hash_buffer(GCRY_MD_BLAKE2S_256, &hash_of_construction,
            construction, strlen(construction));
    return TRUE;
}

/**
 * Computed MAC1. Caller must ensure that GCRY_MD_BLAKE2S_256 is available.
 */
static void
wg_mac1_key(const wg_key_t *static_public, wg_hash_t *mac_key_out)
{
    gcry_md_hd_t hd;
    if (gcry_md_open(&hd, GCRY_MD_BLAKE2S_256, 0) == 0) {
        const char wg_label_mac1[] = "mac1----";
        gcry_md_write(hd, wg_label_mac1, strlen(wg_label_mac1));
        gcry_md_write(hd, static_public, sizeof(wg_key_t));
        memcpy(mac_key_out, gcry_md_read(hd, 0), sizeof(wg_hash_t));
        gcry_md_close(hd);
        return;
    }
    // caller should have checked this.
    g_assert_not_reached();
}

static void
wg_mac(const void *mac_key, guint mac_key_len,
       const guchar *data, guint data_len, wg_mac_t *mac_out)
{
    gcry_md_hd_t hd;
    if (gcry_md_open(&hd, GCRY_MD_BLAKE2S_128, 0) == 0) {
        gcry_error_t r;
        // not documented by Libgcrypt, but required for keyed blake2s
        r = gcry_md_setkey(hd, mac_key, mac_key_len);
        g_assert(r == 0);
        gcry_md_write(hd, data, data_len);
        memcpy(mac_out, gcry_md_read(hd, 0), sizeof(wg_mac_t));
        gcry_md_close(hd);
        return;
    }
    // caller should have checked this.
    g_assert_not_reached();
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

    wg_mac1_key(&keys_out->sender_static.public_key, &keys_out->sender_mac1_key);
    wg_mac1_key(&keys_out->receiver_static_public, &keys_out->receiver_mac1_key);
    dh_x25519(&keys_out->static_dh_secret, &keys_out->receiver_static_public,
            &keys_out->sender_static.private_key);
    return TRUE;
}

gboolean
wg_check_mac1(
    const guchar       *msg,
    guint               msg_len,
    const wg_hash_t    *mac1_key
)
{
    guint hashed_length;

    if (msg_len == 0) {
        g_assert_not_reached(); // TODO remove after test cases are done
        return FALSE;
    }

    switch (msg[0]) {
    case 1: // Initiation
        hashed_length = offsetof(wg_initiation_message_t, mac1);
        break;
    case 2: // Response
        hashed_length = WG_RESPONSE_LENGTH - 32;
        break;
    default:
        g_assert_not_reached(); // TODO remove after test cases are done
        return FALSE;
    }
    if (hashed_length + sizeof(wg_mac_t) > msg_len) {
        g_assert_not_reached(); // TODO remove after test cases are done
        return FALSE;
    }

    const wg_mac_t *msg_mac1 = (wg_mac_t *)&msg[hashed_length];
    wg_mac_t real_mac1;
    wg_mac(mac1_key, sizeof(wg_hash_t), msg, hashed_length, &real_mac1);
    // TODO should this be constant time compare?
    return memcmp(msg_mac1, real_mac1, sizeof(wg_mac_t)) == 0;
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

/**
 * Update the new chained hash value: h = Hash(h || data).
 */
static void
wg_mix_hash(wg_hash_t *h, const void *data, guint data_len)
{
    gcry_md_hd_t hd;
    if (gcry_md_open(&hd, GCRY_MD_BLAKE2S_256, 0)) {
        g_assert_not_reached();
    }
    gcry_md_write(hd, h, sizeof(wg_hash_t));
    gcry_md_write(hd, data, data_len);
    memcpy(h, gcry_md_read(hd, 0), sizeof(wg_hash_t));
    gcry_md_close(hd);
}

/**
 * Computes KDF_n(key, input) where n is the number of derived keys.
 */
static void
wg_kdf(const wg_key_t *key, const void *input, guint input_len, guint n, wg_key_t *out)
{
    guint8          prk[32];    /* Blake2s_256 hash output. */
    gcry_error_t    err;
    err = hkdf_extract(GCRY_MD_BLAKE2S_256, (const guint8 *)key,
            sizeof(wg_key_t), input, input_len, prk);
    g_assert(err == 0);
    err = hkdf_expand(GCRY_MD_BLAKE2S_256, prk, sizeof(prk), NULL, 0, (guint8 *)out, 32 * n);
    g_assert(err == 0);
}

gboolean
wg_process_initiation(
    const guchar       *msg,
    guint               msg_len,
    const wg_keys_t    *keys,
    wg_key_t          **static_public_i,
    guchar            **timestamp
)
{
    if (msg_len != sizeof(wg_initiation_message_t)) {
        g_assert_not_reached(); // TODO remove once tests are complete.
        return FALSE;
    }
    const wg_initiation_message_t *m = (const wg_initiation_message_t *)msg;
    const wg_key_t *static_public_responder;

    // Inputs:
    //  Spub_r, Spub_i, Spriv_i, Epriv_i    if kType = I
    //  Spub_r, Spub_i, Spriv_r             if kType = R
    // Inputs (precomputed):
    //  Spub_r,                  Epriv_i    if kType = I
    //  Spub_r,         Spriv_r             if kType = R
    //  (Spub_i is supposed to be checked against extracted "static" field)
    gboolean is_initiator_keys = TRUE;
    if (is_initiator_keys) {
        static_public_responder = &keys->receiver_static_public;
    } else {
        /* keys from responder */
        static_public_responder = &keys->sender_static.public_key;
    }

    wg_hash_t c_and_k[2], h;
    wg_hash_t *c = &c_and_k[0], *k = &c_and_k[1];
    // c = Hash(CONSTRUCTION)
    memcpy(c, hash_of_construction, sizeof(wg_hash_t));
    // h = Hash(c || msg.sender)
    memcpy(h, c, sizeof(*c));
    wg_mix_hash(&h, m->sender, sizeof(m->sender));
    // h = Hash(h || Spub_r)
    wg_mix_hash(&h, static_public_responder, sizeof(wg_key_t));
    // c = KDF1(c, msg.ephemeral)
    wg_kdf(c, m->ephemeral, sizeof(m->ephemeral), 1, c);
    // h = Hash(h || msg.ephemeral)
    wg_mix_hash(&h, m->ephemeral, sizeof(m->ephemeral));
    //  dh1 = DH(Epriv_i, Spub_r)           if kType = I
    //  dh1 = DH(Spriv_r, msg.ephemeral)    if kType = R
    wg_key_t dh1;
    if (is_initiator_keys) {
        dh_x25519(&dh1, &keys->sender_ephemeral.private_key, static_public_responder);
    } else {
        dh_x25519(&dh1, &keys->sender_static.private_key, (const wg_key_t *)&m->ephemeral);
    }
    // (c, k) = KDF2(c, dh1)
    wg_kdf(c, dh1, sizeof(dh1), 2, c_and_k);
    // Spub_i = AEAD-Decrypt(k, 0, msg.static, h)
    // TODO decrypt using k
    //  -- now check that Spub_i matches in keys "k"
    // h = Hash(h || msg.static)
    wg_mix_hash(&h, m->static_public, sizeof(m->static_public));
    //  dh2 = DH(Spriv_i, Spub_r)           if kType = I
    //  dh2 = DH(Spriv_r, Spub_i)           if kType = R
    // (c, k) = KDF2(c, dh2)
    wg_kdf(c, keys->static_dh_secret, sizeof(wg_key_t), 2, c_and_k);
    // timestamp = AEAD-Decrypt(k, 0, msg.timestamp, h)
    // TODO decrypt timestamp using k
    // h = Hash(h || msg.timestamp)
    wg_mix_hash(&h, m->timestamp, sizeof(m->timestamp));
    // TODO save (h, k) context for responder message processing
    g_assert(!"Not fully implemented");
    return TRUE;
}