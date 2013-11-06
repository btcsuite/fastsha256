/*
 * Copyright (c) 2013 Conformal Systems LLC.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package fastsha256

// #include <sys/types.h>
// #include "sha256.h"
// #cgo CFLAGS: -O3 -static
// #cgo LDFLAGS: -Lobj -lfastsha256
import "C"
import (
	"hash"
	"unsafe"
)

// The size of a SHA256 checksum in bytes.
const Size = C.SHA256_DIGEST_LENGTH

// The blocksize of SHA256 and SHA224 in bytes.
const BlockSize = C.SHA_CBLOCK

type digest struct {
	ctx C._sha256_ctx
}

func Sum256(in []byte) (ret [32]byte) {
	C.openssl_sha256(unsafe.Pointer(&in[0]), C.size_t(len(in)), unsafe.Pointer(&ret[0]))
	return
}

func (d *digest) Size() int {
	return Size
}

func (d *digest) BlockSize() int {
	return BlockSize
}

func (d *digest) Reset() {
	C._sha256_init(&d.ctx)
}

// New returns a new hash.Hash computing the SHA256 checksum.
func New() hash.Hash {
	d := new(digest)
	d.Reset()
	return d
}

func (d0 *digest) Sum(in []byte) []byte {
	// Make a copy of d0 so that caller can keep writing and summing.
	d := *d0
	var ret [Size]byte
	C._sha256_final(unsafe.Pointer(&ret[0]), &d.ctx)
	return append(in, ret[:]...)
}

func (d *digest) Write(in []byte) (nn int, err error) {
	C._sha256_update(&d.ctx, unsafe.Pointer(&in[0]), C.size_t(len(in)))
	return len(in), nil
}
