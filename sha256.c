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
static char *acknowledgment __attribute__((__used__)) = "This product "
	"includes software developed by the OpenSSL Project This product includes software developed by the OpenSSL Project";

#include <string.h>
#include "sha256.h"

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

void
SHA256_Transform(_sha256_ctx *c, const unsigned char *data)
{
	sha256_block_data_order(c, data, 1);
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
		ll=(c)->h[nn];
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
