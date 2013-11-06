/* ====================================================================
 * Copyright (c) 1998-2011 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

static char *version __attribute__((__used__)) = "Copyright (c) 1998-2011 "
	"The OpenSSL Project.  All rights reserved.";
static char *acknowledgment __attribute__((__used__)) = "This product includes "
	"software developed by the OpenSSL Project for use in the OpenSSL "
	"Toolkit (http://www.openssl.org/)";

#include <string.h>
#include "sha256.h"

#define HOST_c2l(c,l)	({ unsigned int r=*((const unsigned int *)(c)); \
	asm ("bswapl %0":"=r"(r):"0"(r));    \
	(c)+=4; (l)=r;                       })
#define HOST_l2c(l,c)	({ unsigned int r=(l);			\
    asm ("bswapl %0":"=r"(r):"0"(r));	\
    *((unsigned int *)(c))=r; (c)+=4; r;	})

void
_sha256_init(_sha256_ctx *c)
{
	memset (c,0,sizeof(*c));
	c->h[0]=0x6a09e667UL;
	c->h[1]=0xbb67ae85UL;
	c->h[2]=0x3c6ef372UL;
	c->h[3]=0xa54ff53aUL;
	c->h[4]=0x510e527fUL;
	c->h[5]=0x9b05688cUL;
	c->h[6]=0x1f83d9abUL;
	c->h[7]=0x5be0cd19UL;
	c->md_len=SHA256_DIGEST_LENGTH;
}

int
_sha256_update(_sha256_ctx *c, const void *data_, size_t len)
{
	const unsigned char	*data=data_;
	unsigned char		*p;
	unsigned int		l;
	size_t			n;

	if (len == 0)
		return 1;

	l = (c->Nl + (((unsigned int)len) << 3)) & 0xffffffffUL;
	if (l < c->Nl) /* overflow */
		c->Nh++;
	c->Nh += (unsigned int)(len >> 29);	/* might cause compiler warning on 16-bit */
	c->Nl = l;

	n = c->num;
	if (n != 0) {
		p = (unsigned char *)c->data;

		if (len >= SHA_CBLOCK || len + n >= SHA_CBLOCK) {
			memcpy(p+n,data,SHA_CBLOCK - n);
			sha256_block_data_order(c, p, 1);
			n = SHA_CBLOCK - n;
			data += n;
			len -= n;
			c->num = 0;
			memset(p, 0, SHA_CBLOCK);	/* keep it zeroed */
		} else {
			memcpy(p + n, data, len);
			c->num += (unsigned int)len;
			return 1;
		}
	}

	n = len / SHA_CBLOCK;
	if (n > 0) {
		sha256_block_data_order(c,data,n);
		n *= SHA_CBLOCK;
		data += n;
		len -= n;
	}

	if (len != 0) {
		p = (unsigned char *)c->data;
		c->num = (unsigned int)len;
		memcpy(p ,data ,len);
	}

	return 1;
}

int
_sha256_final(void *m, _sha256_ctx *c)
{
	unsigned char	*md = m, *p = (unsigned char *)c->data;
	size_t		n = c->num;

	p[n] = 0x80; /* there is always room for one */
	n++;

	if (n > (SHA_CBLOCK - 8)) {
		memset(p +  n, 0, SHA_CBLOCK - n);
		n = 0;
		sha256_block_data_order(c, p, 1);
	}
	memset(p + n, 0, SHA_CBLOCK - 8 - n);

	p += SHA_CBLOCK - 8;
	HOST_l2c(c->Nh, p);
	HOST_l2c(c->Nl, p);
	p -= SHA_CBLOCK;

	sha256_block_data_order(c, p, 1);
	c->num = 0;
	memset(p, 0, SHA_CBLOCK);

	unsigned long ll;
	unsigned int  nn;
	for (nn = 0; nn < SHA256_DIGEST_LENGTH / 4; nn++) {
		ll=c->h[nn];
		HOST_l2c(ll,md);
	}

	return 1;
}

void
openssl_sha256(void *message, size_t len, void *hash)
{
	_sha256_ctx	c;

	_sha256_init(&c);
	_sha256_update(&c, message, len);
	_sha256_final(hash, &c);
}

#ifdef SHA_NOASM
static const unsigned int K256[64] = {
	0x428a2f98UL,0x71374491UL,0xb5c0fbcfUL,0xe9b5dba5UL,
	0x3956c25bUL,0x59f111f1UL,0x923f82a4UL,0xab1c5ed5UL,
	0xd807aa98UL,0x12835b01UL,0x243185beUL,0x550c7dc3UL,
	0x72be5d74UL,0x80deb1feUL,0x9bdc06a7UL,0xc19bf174UL,
	0xe49b69c1UL,0xefbe4786UL,0x0fc19dc6UL,0x240ca1ccUL,
	0x2de92c6fUL,0x4a7484aaUL,0x5cb0a9dcUL,0x76f988daUL,
	0x983e5152UL,0xa831c66dUL,0xb00327c8UL,0xbf597fc7UL,
	0xc6e00bf3UL,0xd5a79147UL,0x06ca6351UL,0x14292967UL,
	0x27b70a85UL,0x2e1b2138UL,0x4d2c6dfcUL,0x53380d13UL,
	0x650a7354UL,0x766a0abbUL,0x81c2c92eUL,0x92722c85UL,
	0xa2bfe8a1UL,0xa81a664bUL,0xc24b8b70UL,0xc76c51a3UL,
	0xd192e819UL,0xd6990624UL,0xf40e3585UL,0x106aa070UL,
	0x19a4c116UL,0x1e376c08UL,0x2748774cUL,0x34b0bcb5UL,
	0x391c0cb3UL,0x4ed8aa4aUL,0x5b9cca4fUL,0x682e6ff3UL,
	0x748f82eeUL,0x78a5636fUL,0x84c87814UL,0x8cc70208UL,
	0x90befffaUL,0xa4506cebUL,0xbef9a3f7UL,0xc67178f2UL };

#define ROTATE(a,n)	({ register unsigned int ret;	\
				asm (			\
				"roll %1,%0"		\
				: "=r"(ret)		\
				: "I"(n), "0"((unsigned int)(a))	\
				: "cc");		\
			   ret;				\
			})

/*
 * FIPS specification refers to right rotations, while our ROTATE macro
 * is left one. This is why you might notice that rotation coefficients
 * differ from those observed in FIPS document by 32-N...
 */
#define Sigma0(x)	(ROTATE((x),30) ^ ROTATE((x),19) ^ ROTATE((x),10))
#define Sigma1(x)	(ROTATE((x),26) ^ ROTATE((x),21) ^ ROTATE((x),7))
#define sigma0(x)	(ROTATE((x),25) ^ ROTATE((x),14) ^ ((x)>>3))
#define sigma1(x)	(ROTATE((x),15) ^ ROTATE((x),13) ^ ((x)>>10))

#define Ch(x,y,z)	(((x) & (y)) ^ ((~(x)) & (z)))
#define Maj(x,y,z)	(((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define	ROUND_00_15(i,a,b,c,d,e,f,g,h)		do {	\
	T1 += h + Sigma1(e) + Ch(e,f,g) + K256[i];	\
	h = Sigma0(a) + Maj(a,b,c);			\
	d += T1;	h += T1;		} while (0)

#define	ROUND_16_63(i,a,b,c,d,e,f,g,h,X)	do {	\
	s0 = X[(i+1)&0x0f];	s0 = sigma0(s0);	\
	s1 = X[(i+14)&0x0f];	s1 = sigma1(s1);	\
	T1 = X[(i)&0x0f] += s0 + s1 + X[(i+9)&0x0f];	\
	ROUND_00_15(i,a,b,c,d,e,f,g,h);		} while (0)

void
sha256_block_data_order(_sha256_ctx *ctx, const void *in, size_t num)
{
	unsigned int a,b,c,d,e,f,g,h,s0,s1,T1;
	unsigned int	X[16];
	int i;
	const unsigned char *data=in;
	const union {
		long one;
		char little;
	} is_endian = {1};

	while (num--) {
		a = ctx->h[0];
		b = ctx->h[1];
		c = ctx->h[2];
		d = ctx->h[3];
		e = ctx->h[4];
		f = ctx->h[5];
		g = ctx->h[6];
		h = ctx->h[7];

		if (!is_endian.little && sizeof(unsigned int) == 4 &&
		    ((size_t)in % 4)==0) {
			const unsigned int *W = (const unsigned int *)data;

			T1 = X[0] = W[0];	ROUND_00_15(0,a,b,c,d,e,f,g,h);
			T1 = X[1] = W[1];	ROUND_00_15(1,h,a,b,c,d,e,f,g);
			T1 = X[2] = W[2];	ROUND_00_15(2,g,h,a,b,c,d,e,f);
			T1 = X[3] = W[3];	ROUND_00_15(3,f,g,h,a,b,c,d,e);
			T1 = X[4] = W[4];	ROUND_00_15(4,e,f,g,h,a,b,c,d);
			T1 = X[5] = W[5];	ROUND_00_15(5,d,e,f,g,h,a,b,c);
			T1 = X[6] = W[6];	ROUND_00_15(6,c,d,e,f,g,h,a,b);
			T1 = X[7] = W[7];	ROUND_00_15(7,b,c,d,e,f,g,h,a);
			T1 = X[8] = W[8];	ROUND_00_15(8,a,b,c,d,e,f,g,h);
			T1 = X[9] = W[9];	ROUND_00_15(9,h,a,b,c,d,e,f,g);
			T1 = X[10] = W[10];	ROUND_00_15(10,g,h,a,b,c,d,e,f);
			T1 = X[11] = W[11];	ROUND_00_15(11,f,g,h,a,b,c,d,e);
			T1 = X[12] = W[12];	ROUND_00_15(12,e,f,g,h,a,b,c,d);
			T1 = X[13] = W[13];	ROUND_00_15(13,d,e,f,g,h,a,b,c);
			T1 = X[14] = W[14];	ROUND_00_15(14,c,d,e,f,g,h,a,b);
			T1 = X[15] = W[15];	ROUND_00_15(15,b,c,d,e,f,g,h,a);

			data += SHA_CBLOCK;
		} else {
			unsigned int l;

			HOST_c2l(data,l); T1 = X[0] = l;  ROUND_00_15(0,a,b,c,d,e,f,g,h);
			HOST_c2l(data,l); T1 = X[1] = l;  ROUND_00_15(1,h,a,b,c,d,e,f,g);
			HOST_c2l(data,l); T1 = X[2] = l;  ROUND_00_15(2,g,h,a,b,c,d,e,f);
			HOST_c2l(data,l); T1 = X[3] = l;  ROUND_00_15(3,f,g,h,a,b,c,d,e);
			HOST_c2l(data,l); T1 = X[4] = l;  ROUND_00_15(4,e,f,g,h,a,b,c,d);
			HOST_c2l(data,l); T1 = X[5] = l;  ROUND_00_15(5,d,e,f,g,h,a,b,c);
			HOST_c2l(data,l); T1 = X[6] = l;  ROUND_00_15(6,c,d,e,f,g,h,a,b);
			HOST_c2l(data,l); T1 = X[7] = l;  ROUND_00_15(7,b,c,d,e,f,g,h,a);
			HOST_c2l(data,l); T1 = X[8] = l;  ROUND_00_15(8,a,b,c,d,e,f,g,h);
			HOST_c2l(data,l); T1 = X[9] = l;  ROUND_00_15(9,h,a,b,c,d,e,f,g);
			HOST_c2l(data,l); T1 = X[10] = l; ROUND_00_15(10,g,h,a,b,c,d,e,f);
			HOST_c2l(data,l); T1 = X[11] = l; ROUND_00_15(11,f,g,h,a,b,c,d,e);
			HOST_c2l(data,l); T1 = X[12] = l; ROUND_00_15(12,e,f,g,h,a,b,c,d);
			HOST_c2l(data,l); T1 = X[13] = l; ROUND_00_15(13,d,e,f,g,h,a,b,c);
			HOST_c2l(data,l); T1 = X[14] = l; ROUND_00_15(14,c,d,e,f,g,h,a,b);
			HOST_c2l(data,l); T1 = X[15] = l; ROUND_00_15(15,b,c,d,e,f,g,h,a);
		}

		for (i = 16; i < 64; i += 8) {
			ROUND_16_63(i+0,a,b,c,d,e,f,g,h,X);
			ROUND_16_63(i+1,h,a,b,c,d,e,f,g,X);
			ROUND_16_63(i+2,g,h,a,b,c,d,e,f,X);
			ROUND_16_63(i+3,f,g,h,a,b,c,d,e,X);
			ROUND_16_63(i+4,e,f,g,h,a,b,c,d,X);
			ROUND_16_63(i+5,d,e,f,g,h,a,b,c,X);
			ROUND_16_63(i+6,c,d,e,f,g,h,a,b,X);
			ROUND_16_63(i+7,b,c,d,e,f,g,h,a,X);
		}

		ctx->h[0] += a;
		ctx->h[1] += b;
		ctx->h[2] += c;
		ctx->h[3] += d;
		ctx->h[4] += e;
		ctx->h[5] += f;
		ctx->h[6] += g;
		ctx->h[7] += h;
	}
}

#endif /* SHA256_ASM */

#ifdef UNIT_TEST
#include <stdio.h>

int
main(int argc, char *argv[])
{
	u_int8_t results[SHA256_DIGEST_LENGTH], *p;
	char *buf;
	int n;
	_sha256_ctx c;

	_sha256_init(&c);
	buf = "abc";
	n = strlen(buf);
	_sha256_update(&c, buf, n);
	_sha256_final(results, &c);

	/* Print the digest as one long hex value */
	printf("0x");
	for (n = 0; n < SHA256_DIGEST_LENGTH; n++)
		printf("%02x", results[n]);
	putchar('\n');

	_sha256_ctx cc;

	_sha256_init(&cc);
	buf = "a";
	_sha256_update(&cc, buf, strlen(buf));
	_sha256_final(results, &cc);
	buf = "b";
	_sha256_update(&cc, buf, strlen(buf));
	_sha256_final(results, &cc);
	buf = "c";
	_sha256_update(&cc, buf, strlen(buf));
	_sha256_final(results, &cc);

	/* Print the digest as one long hex value */
	printf("0x");
	for (n = 0; n < SHA256_DIGEST_LENGTH; n++)
		printf("%02x", results[n]);
	putchar('\n');

	return (0);
}
#endif
