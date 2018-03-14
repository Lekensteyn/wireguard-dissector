/**
 * Cryptographic routines for calculating decryption keys for WireGuard.
 * Copyright (C) 2018 Peter Wu <peter@lekensteyn.nl>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <glib.h>

typedef guchar wg_key_t[32];
/** Output size of the Hash function. */
typedef guchar wg_hash_t[32];
/** MAC1 and MAC2 outputs. */
typedef guchar wg_mac_t[16];
/** Timestamp type (TAI64N). */
typedef guchar wg_tai64n_t[12];

typedef struct {
    wg_key_t    private_key;        ///< Externally supplied.
    wg_key_t    public_key;         ///< Computed from private key.
} wg_keypair_t;

/**
 * External keys (could be from either the initiator or responder).
 */
typedef struct {
    wg_keypair_t    sender_static;
    wg_keypair_t    sender_ephemeral;
    wg_key_t        receiver_static_public;
    wg_key_t        psk;            ///< externally supplied.
    // optimization: pre-expand MAC1 label for static keys
    wg_hash_t       sender_mac1_key;
    wg_hash_t       receiver_mac1_key;
    wg_key_t        static_dh_secret;
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
    const wg_hash_t    *mac1_key
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
    wg_key_t           *static_public_i_out,
    wg_tai64n_t        *timestamp_out,
    wg_hash_t          *hash_out,
    wg_hash_t          *chaining_key_out
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
    const wg_hash_t    *initiator_hash,
    const wg_hash_t    *initiator_chaining_key,
    void               *send_cipher,
    void               *recv_cipher
);
