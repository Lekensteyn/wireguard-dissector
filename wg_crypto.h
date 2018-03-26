/**
 * Cryptographic routines for calculating decryption keys for WireGuard.
 * Copyright (C) 2018 Peter Wu <peter@lekensteyn.nl>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <glib.h>
#include <gcrypt.h>

/** Most operations operate on 32 byte units (keys and hash output). */
typedef guchar wg_qqword[32];
/** MAC1 and MAC2 outputs. */
typedef guchar wg_mac_t[16];
/** Timestamp type (TAI64N). */
typedef guchar wg_tai64n_t[12];

typedef struct {
    wg_qqword       private_key;        ///< Externally supplied.
    wg_qqword       public_key;         ///< Computed from private key.
} wg_keypair_t;

/**
 * External keys (could be from either the initiator or responder).
 */
typedef struct {
    wg_keypair_t    sender_static;
    wg_keypair_t    sender_ephemeral;
    wg_qqword       receiver_static_public;
    wg_qqword       psk;            ///< externally supplied.
    // optimization: pre-expand MAC1 label for static keys
    wg_qqword       sender_mac1_key;
    wg_qqword       receiver_mac1_key;
    wg_qqword       static_dh_secret;
} wg_keys_t;

/**
 * Initialize WG decryption. Returns FALSE if decryption is not possible.
 */
gboolean
wg_decrypt_init(void);

/**
 * Given some base64-encoded keys, derive all other required keys.
 */
gboolean
wg_process_keys(
    wg_keys_t  *keys_out,
    const char *sender_static_private_str,
    const char *receiver_static_public_str,
    const char *sender_ephemeral_private_str,
    const char *psk_str
);

/**
 * Checks whether the given MAC1 is valid for the given message and pre-computed
 * static public key.
 */
gboolean
wg_check_mac1(
    const guchar       *msg,
    guint               msg_len,
    const wg_qqword    *mac1_key
);

/**
 * Tries to compute the initiation message fields.
 * Returns FALSE if decryption failed (e.g. because no valid key is found) and
 * TRUE if decryption succeeded.
 */
gboolean
wg_process_initiation(
    const guchar       *msg,
    guint               msg_len,
    const wg_keys_t    *keys,
    gboolean            is_initiator_keys,
    wg_qqword          *static_public_i_out,
    wg_tai64n_t        *timestamp_out,
    wg_qqword          *hash_out,
    wg_qqword          *chaining_key_out
);

/**
 * Given state from the initiator message, tries to decrypt the response message
 * and generate sender/receiver ciphers.
 */
gboolean
wg_process_response(
    const guchar       *msg,
    guint               msg_len,
    const wg_keys_t    *keys,
    gboolean            is_initiator_keys,
    const wg_qqword    *initiator_ephemeral_public,
    const wg_qqword    *initiator_hash,
    const wg_qqword    *initiator_chaining_key,
    gcry_cipher_hd_t   *initiator_recv_cipher,
    gcry_cipher_hd_t   *responder_recv_cipher
);
