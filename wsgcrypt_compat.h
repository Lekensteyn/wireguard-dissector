/* HKDF routines.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef __WSGCRYPT_H__
#define __WSGCRYPT_H__

/*
 * Extracted from wsutil/wsgcrypt.h and wsutil/wsgcrypt.c.
 * Must be removed when mainlining.
 */

#include <glib.h>
#include <gcrypt.h>

static gcry_error_t
hkdf_expand(int hashalgo, const guint8 *prk, guint prk_len, const guint8 *info, guint info_len,
            guint8 *out, guint out_len)
{
    // Current maximum hash output size: 48 bytes for SHA-384.
    guchar          lastoutput[48];
    gcry_md_hd_t    h;
    gcry_error_t    err;
    const guint     hash_len = gcry_md_get_algo_dlen(hashalgo);

    /* Some sanity checks */
    if (!(out_len > 0 && out_len <= 255 * hash_len) ||
        !(hash_len > 0 && hash_len <= sizeof(lastoutput))) {
        return GPG_ERR_INV_ARG;
    }

    err = gcry_md_open(&h, hashalgo, GCRY_MD_FLAG_HMAC);
    if (err) {
        return err;
    }

    for (guint offset = 0; offset < out_len; offset += hash_len) {
        gcry_md_reset(h);
        gcry_md_setkey(h, prk, prk_len);                    /* Set PRK */
        if (offset > 0) {
            gcry_md_write(h, lastoutput, hash_len);     /* T(1..N) */
        }
        gcry_md_write(h, info, info_len);                   /* info */
        gcry_md_putc(h, (guint8) (offset / hash_len + 1));  /* constant 0x01..N */

        memcpy(lastoutput, gcry_md_read(h, hashalgo), hash_len);
        memcpy(out + offset, lastoutput, MIN(hash_len, out_len - offset));
    }

    gcry_md_close(h);
    return 0;
}

static gcry_error_t ws_hmac_buffer(int algo, void *digest, const void *buffer, size_t length, const void *key, size_t keylen)
{
    gcry_md_hd_t hmac_handle;
    gcry_error_t result = gcry_md_open(&hmac_handle, algo, GCRY_MD_FLAG_HMAC);
    if (result) {
        return result;
    }
    result = gcry_md_setkey(hmac_handle, key, keylen);
    if (result) {
        gcry_md_close(hmac_handle);
        return result;
    }
    gcry_md_write(hmac_handle, buffer, length);
    memcpy(digest, gcry_md_read(hmac_handle, 0), gcry_md_get_algo_dlen(algo));
    gcry_md_close(hmac_handle);
    return GPG_ERR_NO_ERROR;
}

static inline gcry_error_t
hkdf_extract(int hashalgo, const guint8 *salt, size_t salt_len, const guint8 *ikm, size_t ikm_len, guint8 *prk)
{
    /* PRK = HMAC-Hash(salt, IKM) where salt is key, and IKM is input. */
    return ws_hmac_buffer(hashalgo, prk, ikm, ikm_len, salt, salt_len);
}
#endif
