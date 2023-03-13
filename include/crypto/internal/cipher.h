/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2002 James Morris <jmorris@intercode.com.au>
 * Copyright (c) 2002 David S. Miller (davem@redhat.com)
 * Copyright (c) 2005 Herbert Xu <herbert@gondor.apana.org.au>
 *
 * Portions derived from Cryptoapi, by Alexander Kjeldaas <astor@fast.no>
 * and Nettle, by Niels Möller.
 */

#ifndef _CRYPTO_INTERNAL_CIPHER_H
#define _CRYPTO_INTERNAL_CIPHER_H

#include <crypto/algapi.h>

/**
 * crypto_cipher_setkey() - set key for cipher
 * @tfm: cipher handle
 * @key: buffer holding the key
 * @keylen: length of the key in bytes
 *
 * The caller provided key is set for the single block cipher referenced by the
 * cipher handle.
 *
 * Note, the key length determines the cipher type. Many block ciphers implement
 * different cipher modes depending on the key size, such as AES-128 vs AES-192
 * vs. AES-256. When providing a 16 byte key for an AES cipher handle, AES-128
 * is performed.
 *
 * Return: 0 if the setting of the key was successful; < 0 if an error occurred
 */

int crypto_cipher_setkey(struct crypto_cipher *tfm,
			 const u8 *key, unsigned int keylen);

/**
 * crypto_cipher_encrypt_one() - encrypt one block of plaintext
 * @tfm: cipher handle
 * @dst: points to the buffer that will be filled with the ciphertext
 * @src: buffer holding the plaintext to be encrypted
 *
 * Invoke the encryption operation of one block. The caller must ensure that
 * the plaintext and ciphertext buffers are at least one block in size.
 */

void crypto_cipher_encrypt_one(struct crypto_cipher *tfm,
			       u8 *dst, const u8 *src);

/**
 * crypto_cipher_decrypt_one() - decrypt one block of ciphertext
 * @tfm: cipher handle
 * @dst: points to the buffer that will be filled with the plaintext
 * @src: buffer holding the ciphertext to be decrypted
 *
 * Invoke the decryption operation of one block. The caller must ensure that
 * the plaintext and ciphertext buffers are at least one block in size.
 */

void crypto_cipher_decrypt_one(struct crypto_cipher *tfm,
			       u8 *dst, const u8 *src);
             
struct crypto_cipher_spawn {
	struct crypto_spawn base;
};

struct crypto_cipher_spawn_v2 {
	struct crypto_spawn_v2 base;
};

static inline int crypto_grab_cipher(struct crypto_cipher_spawn_v2 *spawn,
				     struct crypto_instance_v2 *inst,
				     const char *name, u32 type, u32 mask)
{
	type &= ~CRYPTO_ALG_TYPE_MASK;
	type |= CRYPTO_ALG_TYPE_CIPHER;
	mask |= CRYPTO_ALG_TYPE_MASK;
	return crypto_grab_spawn_v2(&spawn->base, inst, name, type, mask);
}

static inline void crypto_drop_cipher(struct crypto_cipher_spawn *spawn)
{
	crypto_drop_spawn(&spawn->base);
}

static inline void crypto_drop_cipher_v2(struct crypto_cipher_spawn_v2 *spawn)
{
	crypto_drop_spawn_v2(&spawn->base);
}

static inline struct crypto_alg *crypto_spawn_cipher_alg(
       struct crypto_cipher_spawn *spawn)
{
	return spawn->base.alg;
}

static inline struct crypto_alg *crypto_spawn_cipher_alg_v2(
       struct crypto_cipher_spawn_v2 *spawn)
{
	return spawn->base.alg;
}

static inline struct crypto_cipher *crypto_spawn_cipher_v2(
	struct crypto_cipher_spawn_v2 *spawn)
{
	u32 type = CRYPTO_ALG_TYPE_CIPHER;
	u32 mask = CRYPTO_ALG_TYPE_MASK;

	return __crypto_cipher_cast(crypto_spawn_tfm_v2(&spawn->base, type, mask));
}

#endif