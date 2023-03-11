/*
 * linux/arch/arm64/crypto/aes-modes.S - chaining mode wrappers for AES
 *
 * Copyright (C) 2013 - 2017 Linaro Ltd <ard.biesheuvel@linaro.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

/* included by aes-ce.S and aes-neon.S */

	.text
	.align		4

aes_encrypt_block4x:
	encrypt_block4x	v0, v1, v2, v3, w22, x21, x8, w7
	ret
ENDPROC(aes_encrypt_block4x)

aes_decrypt_block4x:
	decrypt_block4x	v0, v1, v2, v3, w22, x21, x8, w7
	ret
ENDPROC(aes_decrypt_block4x)

	/*
	 * aes_ecb_encrypt(u8 out[], u8 const in[], u8 const rk[], int rounds,
	 *		   int blocks)
	 * aes_ecb_decrypt(u8 out[], u8 const in[], u8 const rk[], int rounds,
	 *		   int blocks)
	 */

AES_ENTRY(aes_ecb_encrypt)
	frame_push	5

	mov		x19, x0
	mov		x20, x1
	mov		x21, x2
	mov		x22, x3
	mov		x23, x4

.Lecbencrestart:
	enc_prepare	w22, x21, x5

.LecbencloopNx:
	subs		w23, w23, #4
	bmi		.Lecbenc1x
	ld1		{v0.16b-v3.16b}, [x20], #64	/* get 4 pt blocks */
	bl		aes_encrypt_block4x
	st1		{v0.16b-v3.16b}, [x19], #64
	cond_yield_neon	.Lecbencrestart
	b		.LecbencloopNx
.Lecbenc1x:
	adds		w23, w23, #4
	beq		.Lecbencout
.Lecbencloop:
	ld1		{v0.16b}, [x20], #16		/* get next pt block */
	encrypt_block	v0, w22, x21, x5, w6
	st1		{v0.16b}, [x19], #16
	subs		w23, w23, #1
	bne		.Lecbencloop
.Lecbencout:
	frame_pop
	ret
AES_ENDPROC(aes_ecb_encrypt)


AES_ENTRY(aes_ecb_decrypt)
	frame_push	5

	mov		x19, x0
	mov		x20, x1
	mov		x21, x2
	mov		x22, x3
	mov		x23, x4

.Lecbdecrestart:
	dec_prepare	w22, x21, x5

.LecbdecloopNx:
	subs		w23, w23, #4
	bmi		.Lecbdec1x
	ld1		{v0.16b-v3.16b}, [x20], #64	/* get 4 ct blocks */
	bl		aes_decrypt_block4x
	st1		{v0.16b-v3.16b}, [x19], #64
	cond_yield_neon	.Lecbdecrestart
	b		.LecbdecloopNx
.Lecbdec1x:
	adds		w23, w23, #4
	beq		.Lecbdecout
.Lecbdecloop:
	ld1		{v0.16b}, [x20], #16		/* get next ct block */
	decrypt_block	v0, w22, x21, x5, w6
	st1		{v0.16b}, [x19], #16
	subs		w23, w23, #1
	bne		.Lecbdecloop
.Lecbdecout:
	frame_pop
	ret
AES_ENDPROC(aes_ecb_decrypt)


	/*
	 * aes_cbc_encrypt(u8 out[], u8 const in[], u8 const rk[], int rounds,
	 *		   int blocks, u8 iv[])
	 * aes_cbc_decrypt(u8 out[], u8 const in[], u8 const rk[], int rounds,
	 *		   int blocks, u8 iv[])
	 */

AES_ENTRY(aes_cbc_encrypt)
	frame_push	6

	mov		x19, x0
	mov		x20, x1
	mov		x21, x2
	mov		x22, x3
	mov		x23, x4
	mov		x24, x5

.Lcbcencrestart:
	ld1		{v4.16b}, [x24]			/* get iv */
	enc_prepare	w22, x21, x6

.Lcbcencloop4x:
	subs		w23, w23, #4
	bmi		.Lcbcenc1x
	ld1		{v0.16b-v3.16b}, [x20], #64	/* get 4 pt blocks */
	eor		v0.16b, v0.16b, v4.16b		/* ..and xor with iv */
	encrypt_block	v0, w22, x21, x6, w7
	eor		v1.16b, v1.16b, v0.16b
	encrypt_block	v1, w22, x21, x6, w7
	eor		v2.16b, v2.16b, v1.16b
	encrypt_block	v2, w22, x21, x6, w7
	eor		v3.16b, v3.16b, v2.16b
	encrypt_block	v3, w22, x21, x6, w7
	st1		{v0.16b-v3.16b}, [x19], #64
	mov		v4.16b, v3.16b
	st1		{v4.16b}, [x24]			/* return iv */
	cond_yield_neon	.Lcbcencrestart
	b		.Lcbcencloop4x
.Lcbcenc1x:
	adds		w23, w23, #4
	beq		.Lcbcencout
.Lcbcencloop:
	ld1		{v0.16b}, [x20], #16		/* get next pt block */
	eor		v4.16b, v4.16b, v0.16b		/* ..and xor with iv */
	encrypt_block	v4, w22, x21, x6, w7
	st1		{v4.16b}, [x19], #16
	subs		w23, w23, #1
	bne		.Lcbcencloop
.Lcbcencout:
	st1		{v4.16b}, [x24]			/* return iv */
	frame_pop
	ret
AES_ENDPROC(aes_cbc_encrypt)


AES_ENTRY(aes_cbc_decrypt)
	frame_push	6

	mov		x19, x0
	mov		x20, x1
	mov		x21, x2
	mov		x22, x3
	mov		x23, x4
	mov		x24, x5

.Lcbcdecrestart:
	ld1		{v7.16b}, [x24]			/* get iv */
	dec_prepare	w22, x21, x6

.LcbcdecloopNx:
	subs		w23, w23, #4
	bmi		.Lcbcdec1x
	ld1		{v0.16b-v3.16b}, [x20], #64	/* get 4 ct blocks */
	mov		v4.16b, v0.16b
	mov		v5.16b, v1.16b
	mov		v6.16b, v2.16b
	bl		aes_decrypt_block4x
	sub		x20, x20, #16
	eor		v0.16b, v0.16b, v7.16b
	eor		v1.16b, v1.16b, v4.16b
	ld1		{v7.16b}, [x20], #16		/* reload 1 ct block */
	eor		v2.16b, v2.16b, v5.16b
	eor		v3.16b, v3.16b, v6.16b
	st1		{v0.16b-v3.16b}, [x19], #64
	st1		{v7.16b}, [x24]			/* return iv */
	cond_yield_neon	.Lcbcdecrestart
	b		.LcbcdecloopNx
.Lcbcdec1x:
	adds		w23, w23, #4
	beq		.Lcbcdecout
.Lcbcdecloop:
	ld1		{v1.16b}, [x20], #16		/* get next ct block */
	mov		v0.16b, v1.16b			/* ...and copy to v0 */
	decrypt_block	v0, w22, x21, x6, w7
	eor		v0.16b, v0.16b, v7.16b		/* xor with iv => pt */
	mov		v7.16b, v1.16b			/* ct is next iv */
	st1		{v0.16b}, [x19], #16
	subs		w23, w23, #1
	bne		.Lcbcdecloop
.Lcbcdecout:
	st1		{v7.16b}, [x24]			/* return iv */
	frame_pop
	ret
AES_ENDPROC(aes_cbc_decrypt)


	 * This macro generates the code for CTR and XCTR mode.
	 */
.macro ctr_encrypt xctr
	// Arguments
	OUT		.req x0
	IN		.req x1
	KEY		.req x2
	ROUNDS_W	.req w3
	BYTES_W		.req w4
	IV		.req x5
	BYTE_CTR_W 	.req w6		// XCTR only
	// Intermediate values
	CTR_W		.req w11	// XCTR only
	CTR		.req x11	// XCTR only
	IV_PART		.req x12
	BLOCKS		.req x13
	BLOCKS_W	.req w13
	frame_push	0
	enc_prepare	ROUNDS_W, KEY, IV_PART
	ld1		{vctr.16b}, [IV]
	/*
	 * Keep 64 bits of the IV in a register.  For CTR mode this lets us
	 * easily increment the IV.  For XCTR mode this lets us efficiently XOR
	 * the 64-bit counter with the IV.
	 */
	.if \xctr
		umov		IV_PART, vctr.d[0]
		lsr		CTR_W, BYTE_CTR_W, #4
	.else
		umov		IV_PART, vctr.d[1]
		rev		IV_PART, IV_PART
	.endif
.LctrloopNx\xctr:
	add		BLOCKS_W, BYTES_W, #15
	sub		BYTES_W, BYTES_W, #MAX_STRIDE << 4
	lsr		BLOCKS_W, BLOCKS_W, #4
	mov		w8, #MAX_STRIDE
	cmp		BLOCKS_W, w8
	csel		BLOCKS_W, BLOCKS_W, w8, lt
	/*
	 * Set up the counter values in v0-v{MAX_STRIDE-1}.
	 *
	 * If we are encrypting less than MAX_STRIDE blocks, the tail block
	 * handling code expects the last keystream block to be in
	 * v{MAX_STRIDE-1}.  For example: if encrypting two blocks with
	 * MAX_STRIDE=5, then v3 and v4 should have the next two counter blocks.
	 */
	.if \xctr
		add		CTR, CTR, BLOCKS
	.else
		adds		IV_PART, IV_PART, BLOCKS
	.endif
	mov		v0.16b, vctr.16b
	mov		v1.16b, vctr.16b
	mov		v2.16b, vctr.16b
	mov		v3.16b, vctr.16b
ST5(	mov		v4.16b, vctr.16b		)
	.if \xctr
		sub		x6, CTR, #MAX_STRIDE - 1
		sub		x7, CTR, #MAX_STRIDE - 2
		sub		x8, CTR, #MAX_STRIDE - 3
		sub		x9, CTR, #MAX_STRIDE - 4
ST5(		sub		x10, CTR, #MAX_STRIDE - 5	)
		eor		x6, x6, IV_PART
		eor		x7, x7, IV_PART
		eor		x8, x8, IV_PART
		eor		x9, x9, IV_PART
ST5(		eor		x10, x10, IV_PART		)
		mov		v0.d[0], x6
		mov		v1.d[0], x7
		mov		v2.d[0], x8
		mov		v3.d[0], x9
ST5(		mov		v4.d[0], x10			)
	.else
		bcs		0f
		.subsection	1
		/*
		 * This subsection handles carries.
		 *
		 * Conditional branching here is allowed with respect to time
		 * invariance since the branches are dependent on the IV instead
		 * of the plaintext or key.  This code is rarely executed in
		 * practice anyway.
		 */
		/* Apply carry to outgoing counter. */
0:		umov		x8, vctr.d[0]
		rev		x8, x8
		add		x8, x8, #1
		rev		x8, x8
		ins		vctr.d[0], x8
		/*
		 * Apply carry to counter blocks if needed.
		 *
		 * Since the carry flag was set, we know 0 <= IV_PART <
		 * MAX_STRIDE.  Using the value of IV_PART we can determine how
		 * many counter blocks need to be updated.
		 */
		cbz		IV_PART, 2f
		adr		x16, 1f
		sub		x16, x16, IV_PART, lsl #3
		br		x16
		bti		c
		mov		v0.d[0], vctr.d[0]
		bti		c
		mov		v1.d[0], vctr.d[0]
		bti		c
		mov		v2.d[0], vctr.d[0]
		bti		c
		mov		v3.d[0], vctr.d[0]
ST5(		bti		c				)
ST5(		mov		v4.d[0], vctr.d[0]		)
1:		b		2f
		.previous
2:		rev		x7, IV_PART
		ins		vctr.d[1], x7
		sub		x7, IV_PART, #MAX_STRIDE - 1
		sub		x8, IV_PART, #MAX_STRIDE - 2
		sub		x9, IV_PART, #MAX_STRIDE - 3
		rev		x7, x7
		rev		x8, x8
		mov		v1.d[1], x7
		rev		x9, x9
ST5(		sub		x10, IV_PART, #MAX_STRIDE - 4	)
		mov		v2.d[1], x8
ST5(		rev		x10, x10			)
		mov		v3.d[1], x9
ST5(		mov		v4.d[1], x10			)
	.endif
	/*
	 * If there are at least MAX_STRIDE blocks left, XOR the data with
	 * keystream and store.  Otherwise jump to tail handling.
	 */
	tbnz		BYTES_W, #31, .Lctrtail\xctr
	ld1		{v5.16b-v7.16b}, [IN], #48
ST4(	bl		aes_encrypt_block4x		)
ST5(	bl		aes_encrypt_block5x		)
	eor		v0.16b, v5.16b, v0.16b
ST4(	ld1		{v5.16b}, [IN], #16		)
	eor		v1.16b, v6.16b, v1.16b
ST5(	ld1		{v5.16b-v6.16b}, [IN], #32	)
	eor		v2.16b, v7.16b, v2.16b
	eor		v3.16b, v5.16b, v3.16b
ST5(	eor		v4.16b, v6.16b, v4.16b		)
	st1		{v0.16b-v3.16b}, [OUT], #64
ST5(	st1		{v4.16b}, [OUT], #16		)
	cbz		BYTES_W, .Lctrout\xctr
	b		.LctrloopNx\xctr
.Lctrout\xctr:
	.if !\xctr
		st1		{vctr.16b}, [IV] /* return next CTR value */
	.endif
	frame_pop
	ret
.Lctrtail\xctr:
	/*
	 * Handle up to MAX_STRIDE * 16 - 1 bytes of plaintext
	 *
	 * This code expects the last keystream block to be in v{MAX_STRIDE-1}.
	 * For example: if encrypting two blocks with MAX_STRIDE=5, then v3 and
	 * v4 should have the next two counter blocks.
	 *
	 * This allows us to store the ciphertext by writing to overlapping
	 * regions of memory.  Any invalid ciphertext blocks get overwritten by
	 * correctly computed blocks.  This approach greatly simplifies the
	 * logic for storing the ciphertext.
	 */
	mov		x16, #16
	ands		w7, BYTES_W, #0xf
	csel		x13, x7, x16, ne
ST5(	cmp		BYTES_W, #64 - (MAX_STRIDE << 4))
ST5(	csel		x14, x16, xzr, gt		)
	cmp		BYTES_W, #48 - (MAX_STRIDE << 4)
	csel		x15, x16, xzr, gt
	cmp		BYTES_W, #32 - (MAX_STRIDE << 4)
	csel		x16, x16, xzr, gt
	cmp		BYTES_W, #16 - (MAX_STRIDE << 4)
	adr_l		x9, .Lcts_permute_table
	add		x9, x9, x13
	ble		.Lctrtail1x\xctr
ST5(	ld1		{v5.16b}, [IN], x14		)
	ld1		{v6.16b}, [IN], x15
	ld1		{v7.16b}, [IN], x16
ST4(	bl		aes_encrypt_block4x		)
ST5(	bl		aes_encrypt_block5x		)
	ld1		{v8.16b}, [IN], x13
	ld1		{v9.16b}, [IN]
	ld1		{v10.16b}, [x9]
ST4(	eor		v6.16b, v6.16b, v0.16b		)
ST4(	eor		v7.16b, v7.16b, v1.16b		)
ST4(	tbl		v3.16b, {v3.16b}, v10.16b	)
ST4(	eor		v8.16b, v8.16b, v2.16b		)
ST4(	eor		v9.16b, v9.16b, v3.16b		)
ST5(	eor		v5.16b, v5.16b, v0.16b		)
ST5(	eor		v6.16b, v6.16b, v1.16b		)
ST5(	tbl		v4.16b, {v4.16b}, v10.16b	)
ST5(	eor		v7.16b, v7.16b, v2.16b		)
ST5(	eor		v8.16b, v8.16b, v3.16b		)
ST5(	eor		v9.16b, v9.16b, v4.16b		)
ST5(	st1		{v5.16b}, [OUT], x14		)
	st1		{v6.16b}, [OUT], x15
	st1		{v7.16b}, [OUT], x16
	add		x13, x13, OUT
	st1		{v9.16b}, [x13]		// overlapping stores
	st1		{v8.16b}, [OUT]
	b		.Lctrout\xctr
.Lctrtail1x\xctr:
	/*
	 * Handle <= 16 bytes of plaintext
	 *
	 * This code always reads and writes 16 bytes.  To avoid out of bounds
	 * accesses, XCTR and CTR modes must use a temporary buffer when
	 * encrypting/decrypting less than 16 bytes.
	 *
	 * This code is unusual in that it loads the input and stores the output
	 * relative to the end of the buffers rather than relative to the start.
	 * This causes unusual behaviour when encrypting/decrypting less than 16
	 * bytes; the end of the data is expected to be at the end of the
	 * temporary buffer rather than the start of the data being at the start
	 * of the temporary buffer.
	 */
	sub		x8, x7, #16
	csel		x7, x7, x8, eq
	add		IN, IN, x7
	add		OUT, OUT, x7
	ld1		{v5.16b}, [IN]
	ld1		{v6.16b}, [OUT]
ST5(	mov		v3.16b, v4.16b			)
	encrypt_block	v3, ROUNDS_W, KEY, x8, w7
	ld1		{v10.16b-v11.16b}, [x9]
	tbl		v3.16b, {v3.16b}, v10.16b
	sshr		v11.16b, v11.16b, #7
	eor		v5.16b, v5.16b, v3.16b
	bif		v5.16b, v6.16b, v11.16b
	st1		{v5.16b}, [OUT]
	b		.Lctrout\xctr
	// Arguments
	.unreq OUT
	.unreq IN
	.unreq KEY
	.unreq ROUNDS_W
	.unreq BYTES_W
	.unreq IV
	.unreq BYTE_CTR_W	// XCTR only
	// Intermediate values
	.unreq CTR_W		// XCTR only
	.unreq CTR		// XCTR only
	.unreq IV_PART
	.unreq BLOCKS
	.unreq BLOCKS_W
.endm

	/*
	 * aes_xctr_encrypt(u8 out[], u8 const in[], u8 const rk[], int rounds,
	 *		   int bytes, u8 const iv[], int byte_ctr)
	 *
	 * The input and output buffers must always be at least 16 bytes even if
	 * encrypting/decrypting less than 16 bytes.  Otherwise out of bounds
	 * accesses will occur.  The data to be encrypted/decrypted is expected
	 * to be at the end of this 16-byte temporary buffer rather than the
	 * start.
	 */

AES_ENTRY(aes_xctr_encrypt)
	ctr_encrypt 1
AES_ENDPROC(aes_xctr_encrypt)

	/*
	 * aes_ctr_encrypt(u8 out[], u8 const in[], u8 const rk[], int rounds,
	 *		   int blocks, u8 ctr[])
	 */

AES_ENTRY(aes_ctr_encrypt)
	frame_push	6

	mov		x19, x0
	mov		x20, x1
	mov		x21, x2
	mov		x22, x3
	mov		x23, x4
	mov		x24, x5

.Lctrrestart:
	enc_prepare	w22, x21, x6
	ld1		{v4.16b}, [x24]

	umov		x6, v4.d[1]		/* keep swabbed ctr in reg */
	rev		x6, x6
.LctrloopNx:
	subs		w23, w23, #4
	bmi		.Lctr1x
	cmn		w6, #4			/* 32 bit overflow? */
	bcs		.Lctr1x
	add		w7, w6, #1
	mov		v0.16b, v4.16b
	add		w8, w6, #2
	mov		v1.16b, v4.16b
	add		w9, w6, #3
	mov		v2.16b, v4.16b
	rev		w7, w7
	mov		v3.16b, v4.16b
	rev		w8, w8
	mov		v1.s[3], w7
	rev		w9, w9
	mov		v2.s[3], w8
	mov		v3.s[3], w9
	ld1		{v5.16b-v7.16b}, [x20], #48	/* get 3 input blocks */
	bl		aes_encrypt_block4x
	eor		v0.16b, v5.16b, v0.16b
	ld1		{v5.16b}, [x20], #16		/* get 1 input block  */
	eor		v1.16b, v6.16b, v1.16b
	eor		v2.16b, v7.16b, v2.16b
	eor		v3.16b, v5.16b, v3.16b
	st1		{v0.16b-v3.16b}, [x19], #64
	add		x6, x6, #4
	rev		x7, x6
	ins		v4.d[1], x7
	cbz		w23, .Lctrout
	st1		{v4.16b}, [x24]		/* return next CTR value */
	cond_yield_neon	.Lctrrestart
	b		.LctrloopNx
.Lctr1x:
	adds		w23, w23, #4
	beq		.Lctrout
.Lctrloop:
	mov		v0.16b, v4.16b
	encrypt_block	v0, w22, x21, x8, w7

	adds		x6, x6, #1		/* increment BE ctr */
	rev		x7, x6
	ins		v4.d[1], x7
	bcs		.Lctrcarry		/* overflow? */

.Lctrcarrydone:
	subs		w23, w23, #1
	bmi		.Lctrtailblock		/* blocks <0 means tail block */
	ld1		{v3.16b}, [x20], #16
	eor		v3.16b, v0.16b, v3.16b
	st1		{v3.16b}, [x19], #16
	bne		.Lctrloop

.Lctrout:
	st1		{v4.16b}, [x24]		/* return next CTR value */
.Lctrret:
	frame_pop
	ret

.Lctrtailblock:
	st1		{v0.16b}, [x19]
	b		.Lctrret

.Lctrcarry:
	umov		x7, v4.d[0]		/* load upper word of ctr  */
	rev		x7, x7			/* ... to handle the carry */
	add		x7, x7, #1
	rev		x7, x7
	ins		v4.d[0], x7
	b		.Lctrcarrydone
AES_ENDPROC(aes_ctr_encrypt)
	.ltorg


	/*
	 * aes_xts_decrypt(u8 out[], u8 const in[], u8 const rk1[], int rounds,
	 *		   int blocks, u8 const rk2[], u8 iv[], int first)
	 * aes_xts_decrypt(u8 out[], u8 const in[], u8 const rk1[], int rounds,
	 *		   int blocks, u8 const rk2[], u8 iv[], int first)
	 */

	.macro		next_tweak, out, in, const, tmp
	sshr		\tmp\().2d,  \in\().2d,   #63
	and		\tmp\().16b, \tmp\().16b, \const\().16b
	add		\out\().2d,  \in\().2d,   \in\().2d
	ext		\tmp\().16b, \tmp\().16b, \tmp\().16b, #8
	eor		\out\().16b, \out\().16b, \tmp\().16b
	.endm

.Lxts_mul_x:
CPU_LE(	.quad		1, 0x87		)
CPU_BE(	.quad		0x87, 1		)

AES_ENTRY(aes_xts_encrypt)
	frame_push	6

	mov		x19, x0
	mov		x20, x1
	mov		x21, x2
	mov		x22, x3
	mov		x23, x4
	mov		x24, x6

	ld1		{v4.16b}, [x24]
	cbz		w7, .Lxtsencnotfirst

	enc_prepare	w3, x5, x8
	encrypt_block	v4, w3, x5, x8, w7		/* first tweak */
	enc_switch_key	w3, x2, x8
	ldr		q7, .Lxts_mul_x
	b		.LxtsencNx

.Lxtsencrestart:
	ld1		{v4.16b}, [x24]
.Lxtsencnotfirst:
	enc_prepare	w22, x21, x8
.LxtsencloopNx:
	ldr		q7, .Lxts_mul_x
	next_tweak	v4, v4, v7, v8
.LxtsencNx:
	subs		w23, w23, #4
	bmi		.Lxtsenc1x
	ld1		{v0.16b-v3.16b}, [x20], #64	/* get 4 pt blocks */
	next_tweak	v5, v4, v7, v8
	eor		v0.16b, v0.16b, v4.16b
	next_tweak	v6, v5, v7, v8
	eor		v1.16b, v1.16b, v5.16b
	eor		v2.16b, v2.16b, v6.16b
	next_tweak	v7, v6, v7, v8
	eor		v3.16b, v3.16b, v7.16b
	bl		aes_encrypt_block4x
	eor		v3.16b, v3.16b, v7.16b
	eor		v0.16b, v0.16b, v4.16b
	eor		v1.16b, v1.16b, v5.16b
	eor		v2.16b, v2.16b, v6.16b
	st1		{v0.16b-v3.16b}, [x19], #64
	mov		v4.16b, v7.16b
	cbz		w23, .Lxtsencout
	st1		{v4.16b}, [x24]
	cond_yield_neon	.Lxtsencrestart
	b		.LxtsencloopNx
.Lxtsenc1x:
	adds		w23, w23, #4
	beq		.Lxtsencout
.Lxtsencloop:
	ld1		{v1.16b}, [x20], #16
	eor		v0.16b, v1.16b, v4.16b
	encrypt_block	v0, w22, x21, x8, w7
	eor		v0.16b, v0.16b, v4.16b
	st1		{v0.16b}, [x19], #16
	subs		w23, w23, #1
	beq		.Lxtsencout
	next_tweak	v4, v4, v7, v8
	b		.Lxtsencloop
.Lxtsencout:
	st1		{v4.16b}, [x24]
	frame_pop
	ret
AES_ENDPROC(aes_xts_encrypt)


AES_ENTRY(aes_xts_decrypt)
	frame_push	6

	mov		x19, x0
	mov		x20, x1
	mov		x21, x2
	mov		x22, x3
	mov		x23, x4
	mov		x24, x6

	ld1		{v4.16b}, [x24]
	cbz		w7, .Lxtsdecnotfirst

	enc_prepare	w3, x5, x8
	encrypt_block	v4, w3, x5, x8, w7		/* first tweak */
	dec_prepare	w3, x2, x8
	ldr		q7, .Lxts_mul_x
	b		.LxtsdecNx

.Lxtsdecrestart:
	ld1		{v4.16b}, [x24]
.Lxtsdecnotfirst:
	dec_prepare	w22, x21, x8
.LxtsdecloopNx:
	ldr		q7, .Lxts_mul_x
	next_tweak	v4, v4, v7, v8
.LxtsdecNx:
	subs		w23, w23, #4
	bmi		.Lxtsdec1x
	ld1		{v0.16b-v3.16b}, [x20], #64	/* get 4 ct blocks */
	next_tweak	v5, v4, v7, v8
	eor		v0.16b, v0.16b, v4.16b
	next_tweak	v6, v5, v7, v8
	eor		v1.16b, v1.16b, v5.16b
	eor		v2.16b, v2.16b, v6.16b
	next_tweak	v7, v6, v7, v8
	eor		v3.16b, v3.16b, v7.16b
	bl		aes_decrypt_block4x
	eor		v3.16b, v3.16b, v7.16b
	eor		v0.16b, v0.16b, v4.16b
	eor		v1.16b, v1.16b, v5.16b
	eor		v2.16b, v2.16b, v6.16b
	st1		{v0.16b-v3.16b}, [x19], #64
	mov		v4.16b, v7.16b
	cbz		w23, .Lxtsdecout
	st1		{v4.16b}, [x24]
	cond_yield_neon	.Lxtsdecrestart
	b		.LxtsdecloopNx
.Lxtsdec1x:
	adds		w23, w23, #4
	beq		.Lxtsdecout
.Lxtsdecloop:
	ld1		{v1.16b}, [x20], #16
	eor		v0.16b, v1.16b, v4.16b
	decrypt_block	v0, w22, x21, x8, w7
	eor		v0.16b, v0.16b, v4.16b
	st1		{v0.16b}, [x19], #16
	subs		w23, w23, #1
	beq		.Lxtsdecout
	next_tweak	v4, v4, v7, v8
	b		.Lxtsdecloop
.Lxtsdecout:
	st1		{v4.16b}, [x24]
	frame_pop
	ret
AES_ENDPROC(aes_xts_decrypt)

	/*
	 * aes_mac_update(u8 const in[], u32 const rk[], int rounds,
	 *		  int blocks, u8 dg[], int enc_before, int enc_after)
	 */
AES_ENTRY(aes_mac_update)
	frame_push	6

	mov		x19, x0
	mov		x20, x1
	mov		x21, x2
	mov		x22, x3
	mov		x23, x4
	mov		x24, x6

	ld1		{v0.16b}, [x23]			/* get dg */
	enc_prepare	w2, x1, x7
	cbz		w5, .Lmacloop4x

	encrypt_block	v0, w2, x1, x7, w8

.Lmacloop4x:
	subs		w22, w22, #4
	bmi		.Lmac1x
	ld1		{v1.16b-v4.16b}, [x19], #64	/* get next pt block */
	eor		v0.16b, v0.16b, v1.16b		/* ..and xor with dg */
	encrypt_block	v0, w21, x20, x7, w8
	eor		v0.16b, v0.16b, v2.16b
	encrypt_block	v0, w21, x20, x7, w8
	eor		v0.16b, v0.16b, v3.16b
	encrypt_block	v0, w21, x20, x7, w8
	eor		v0.16b, v0.16b, v4.16b
	cmp		w22, wzr
	csinv		x5, x24, xzr, eq
	cbz		w5, .Lmacout
	encrypt_block	v0, w21, x20, x7, w8
	st1		{v0.16b}, [x23]			/* return dg */
	cond_yield_neon	.Lmacrestart
	b		.Lmacloop4x
.Lmac1x:
	add		w22, w22, #4
.Lmacloop:
	cbz		w22, .Lmacout
	ld1		{v1.16b}, [x19], #16		/* get next pt block */
	eor		v0.16b, v0.16b, v1.16b		/* ..and xor with dg */

	subs		w22, w22, #1
	csinv		x5, x24, xzr, eq
	cbz		w5, .Lmacout

.Lmacenc:
	encrypt_block	v0, w21, x20, x7, w8
	b		.Lmacloop

.Lmacout:
	st1		{v0.16b}, [x23]			/* return dg */
	frame_pop
	ret

.Lmacrestart:
	ld1		{v0.16b}, [x23]			/* get dg */
	enc_prepare	w21, x20, x0
	b		.Lmacloop4x
AES_ENDPROC(aes_mac_update)
