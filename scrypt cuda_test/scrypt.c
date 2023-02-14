#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <Windows.h>
__int64 cpucycles() {
	return __rdtsc();
}
#define R(a,b)	(((a) << (b)) | ((a) >> (32-(b))))

#define GPU_SHA256_DIGEST		32
#define GPU_SHA256_BLOCK		64
#define GPU_add3(a, b, c)		(a + b + c)
#define GPU_rotl32(x, n)		(((x) << (n)) | ((x) >> (32 - (n))))
#define GPU_rotr32(x, n)		(((x) >> (n)) | ((x) << (32 - (n))))
#define GPU_SHIFT_RIGHT_32(x,n) ((x) >> (n))
#define GPU_SHA256_F0(x,y,z)	(((x) & (y)) | ((z) & ((x) ^ (y))))
#define GPU_SHA256_F1(x,y,z)	((z) ^ ((x) & ((y) ^ (z))))
#define GPU_SHA256_F0o(x,y,z) (GPU_SHA256_F0 ((x), (y), (z)))
#define GPU_SHA256_F1o(x,y,z) (GPU_SHA256_F1 ((x), (y), (z)))
#define GPU_SHA256_S0(x) (GPU_rotl32 ((x), 25u) ^ GPU_rotl32 ((x), 14u) ^ GPU_SHIFT_RIGHT_32 ((x),  3u))
#define GPU_SHA256_S1(x) (GPU_rotl32 ((x), 15u) ^ GPU_rotl32 ((x), 13u) ^ GPU_SHIFT_RIGHT_32 ((x), 10u))
#define GPU_SHA256_S2(x) (GPU_rotl32 ((x), 30u) ^ GPU_rotl32 ((x), 19u) ^ GPU_rotl32 ((x), 10u))
#define GPU_SHA256_S3(x) (GPU_rotl32 ((x), 26u) ^ GPU_rotl32 ((x), 21u) ^ GPU_rotl32 ((x),  7u))
#define GPU_SHA256_EXPAND(x,y,z,w) (GPU_SHA256_S1 (x) + y + GPU_SHA256_S0 (z) + w)
#define GPU_SHA256_STEP(F0,F1,a,b,c,d,e,f,g,h,x,K)    \
{                                                 \
  h = GPU_add3 (h, K, x);                          \
  h = GPU_add3 (h, GPU_SHA256_S3 (e), F1 (e,f,g));     \
  d += h;                                         \
  h = GPU_add3 (h, GPU_SHA256_S2 (a), F0 (a,b,c));     \
}
typedef struct {
	uint32_t digest[8];
	uint64_t ptLen;
	uint8_t BUF[GPU_SHA256_BLOCK];
	uint32_t lastLen;
}SHA256_INFO;
typedef struct {
	uint32_t IPAD[8];
	uint32_t OPAD[8];
	uint64_t ptLen;
}PBKDF2_HMAC_SHA256_INFO;
#define GPU_ENDIAN_CHANGE32(X)		((GPU_rotl32((X),  8) & 0x00ff00ff) | (GPU_rotl32((X), 24) & 0xff00ff00))

void _SHA256_init(SHA256_INFO* info) {
	info->digest[0] = 0x6a09e667;
	info->digest[1] = 0xbb67ae85;
	info->digest[2] = 0x3c6ef372;
	info->digest[3] = 0xa54ff53a;
	info->digest[4] = 0x510e527f;
	info->digest[5] = 0x9b05688c;
	info->digest[6] = 0x1f83d9ab;
	info->digest[7] = 0x5be0cd19;

	for (int i = 0; i < GPU_SHA256_BLOCK; i++) {
		info->BUF[i] = 0;
	}
	info->ptLen = 0, info->lastLen = 0;
}
void _SHA256_core(uint32_t* input, uint32_t* digest) {
	uint32_t a, b, c, d, e, f, g, h;
	uint32_t w0_t = GPU_ENDIAN_CHANGE32(input[0]);
	uint32_t w1_t = GPU_ENDIAN_CHANGE32(input[1]);
	uint32_t w2_t = GPU_ENDIAN_CHANGE32(input[2]);
	uint32_t w3_t = GPU_ENDIAN_CHANGE32(input[3]);
	uint32_t w4_t = GPU_ENDIAN_CHANGE32(input[4]);
	uint32_t w5_t = GPU_ENDIAN_CHANGE32(input[5]);
	uint32_t w6_t = GPU_ENDIAN_CHANGE32(input[6]);
	uint32_t w7_t = GPU_ENDIAN_CHANGE32(input[7]);
	uint32_t w8_t = GPU_ENDIAN_CHANGE32(input[8]);
	uint32_t w9_t = GPU_ENDIAN_CHANGE32(input[9]);
	uint32_t wa_t = GPU_ENDIAN_CHANGE32(input[10]);
	uint32_t wb_t = GPU_ENDIAN_CHANGE32(input[11]);
	uint32_t wc_t = GPU_ENDIAN_CHANGE32(input[12]);
	uint32_t wd_t = GPU_ENDIAN_CHANGE32(input[13]);
	uint32_t we_t = GPU_ENDIAN_CHANGE32(input[14]);
	uint32_t wf_t = GPU_ENDIAN_CHANGE32(input[15]);

	a = digest[0];
	b = digest[1];
	c = digest[2];
	d = digest[3];
	e = digest[4];
	f = digest[5];
	g = digest[6];
	h = digest[7];

	GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, 0x428a2f98);
	GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, 0x71374491);
	GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, 0xb5c0fbcf);
	GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, 0xe9b5dba5);
	GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, 0x3956c25b);
	GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, 0x59f111f1);
	GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, 0x923f82a4);
	GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, 0xab1c5ed5);
	GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, 0xd807aa98);
	GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, 0x12835b01);
	GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, 0x243185be);
	GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, 0x550c7dc3);
	GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, 0x72be5d74);
	GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, 0x80deb1fe);
	GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, c, d, e, f, g, h, a, b, we_t, 0x9bdc06a7);
	GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, 0xc19bf174);

	w0_t = GPU_SHA256_EXPAND(we_t, w9_t, w1_t, w0_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, 0xe49b69c1);
	w1_t = GPU_SHA256_EXPAND(wf_t, wa_t, w2_t, w1_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, 0xefbe4786);
	w2_t = GPU_SHA256_EXPAND(w0_t, wb_t, w3_t, w2_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, 0x0fc19dc6);
	w3_t = GPU_SHA256_EXPAND(w1_t, wc_t, w4_t, w3_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, 0x240ca1cc);
	w4_t = GPU_SHA256_EXPAND(w2_t, wd_t, w5_t, w4_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, 0x2de92c6f);
	w5_t = GPU_SHA256_EXPAND(w3_t, we_t, w6_t, w5_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, 0x4a7484aa);
	w6_t = GPU_SHA256_EXPAND(w4_t, wf_t, w7_t, w6_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, 0x5cb0a9dc);
	w7_t = GPU_SHA256_EXPAND(w5_t, w0_t, w8_t, w7_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, 0x76f988da);
	w8_t = GPU_SHA256_EXPAND(w6_t, w1_t, w9_t, w8_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, 0x983e5152);
	w9_t = GPU_SHA256_EXPAND(w7_t, w2_t, wa_t, w9_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, 0xa831c66d);
	wa_t = GPU_SHA256_EXPAND(w8_t, w3_t, wb_t, wa_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, 0xb00327c8);
	wb_t = GPU_SHA256_EXPAND(w9_t, w4_t, wc_t, wb_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, 0xbf597fc7);
	wc_t = GPU_SHA256_EXPAND(wa_t, w5_t, wd_t, wc_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, 0xc6e00bf3);
	wd_t = GPU_SHA256_EXPAND(wb_t, w6_t, we_t, wd_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, 0xd5a79147);
	we_t = GPU_SHA256_EXPAND(wc_t, w7_t, wf_t, we_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, c, d, e, f, g, h, a, b, we_t, 0x06ca6351);
	wf_t = GPU_SHA256_EXPAND(wd_t, w8_t, w0_t, wf_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, 0x14292967);

	w0_t = GPU_SHA256_EXPAND(we_t, w9_t, w1_t, w0_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, 0x27b70a85);
	w1_t = GPU_SHA256_EXPAND(wf_t, wa_t, w2_t, w1_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, 0x2e1b2138);
	w2_t = GPU_SHA256_EXPAND(w0_t, wb_t, w3_t, w2_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, 0x4d2c6dfc);
	w3_t = GPU_SHA256_EXPAND(w1_t, wc_t, w4_t, w3_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, 0x53380d13);
	w4_t = GPU_SHA256_EXPAND(w2_t, wd_t, w5_t, w4_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, 0x650a7354);
	w5_t = GPU_SHA256_EXPAND(w3_t, we_t, w6_t, w5_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, 0x766a0abb);
	w6_t = GPU_SHA256_EXPAND(w4_t, wf_t, w7_t, w6_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, 0x81c2c92e);
	w7_t = GPU_SHA256_EXPAND(w5_t, w0_t, w8_t, w7_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, 0x92722c85);
	w8_t = GPU_SHA256_EXPAND(w6_t, w1_t, w9_t, w8_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, 0xa2bfe8a1);
	w9_t = GPU_SHA256_EXPAND(w7_t, w2_t, wa_t, w9_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, 0xa81a664b);
	wa_t = GPU_SHA256_EXPAND(w8_t, w3_t, wb_t, wa_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, 0xc24b8b70);
	wb_t = GPU_SHA256_EXPAND(w9_t, w4_t, wc_t, wb_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, 0xc76c51a3);
	wc_t = GPU_SHA256_EXPAND(wa_t, w5_t, wd_t, wc_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, 0xd192e819);
	wd_t = GPU_SHA256_EXPAND(wb_t, w6_t, we_t, wd_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, 0xd6990624);
	we_t = GPU_SHA256_EXPAND(wc_t, w7_t, wf_t, we_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, c, d, e, f, g, h, a, b, we_t, 0xf40e3585);
	wf_t = GPU_SHA256_EXPAND(wd_t, w8_t, w0_t, wf_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, 0x106aa070);

	w0_t = GPU_SHA256_EXPAND(we_t, w9_t, w1_t, w0_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, 0x19a4c116);
	w1_t = GPU_SHA256_EXPAND(wf_t, wa_t, w2_t, w1_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, 0x1e376c08);
	w2_t = GPU_SHA256_EXPAND(w0_t, wb_t, w3_t, w2_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, 0x2748774c);
	w3_t = GPU_SHA256_EXPAND(w1_t, wc_t, w4_t, w3_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, 0x34b0bcb5);
	w4_t = GPU_SHA256_EXPAND(w2_t, wd_t, w5_t, w4_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, 0x391c0cb3);
	w5_t = GPU_SHA256_EXPAND(w3_t, we_t, w6_t, w5_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, 0x4ed8aa4a);
	w6_t = GPU_SHA256_EXPAND(w4_t, wf_t, w7_t, w6_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, 0x5b9cca4f);
	w7_t = GPU_SHA256_EXPAND(w5_t, w0_t, w8_t, w7_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, 0x682e6ff3);
	w8_t = GPU_SHA256_EXPAND(w6_t, w1_t, w9_t, w8_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, 0x748f82ee);
	w9_t = GPU_SHA256_EXPAND(w7_t, w2_t, wa_t, w9_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, 0x78a5636f);
	wa_t = GPU_SHA256_EXPAND(w8_t, w3_t, wb_t, wa_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, 0x84c87814);
	wb_t = GPU_SHA256_EXPAND(w9_t, w4_t, wc_t, wb_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, 0x8cc70208);
	wc_t = GPU_SHA256_EXPAND(wa_t, w5_t, wd_t, wc_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, 0x90befffa);
	wd_t = GPU_SHA256_EXPAND(wb_t, w6_t, we_t, wd_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, 0xa4506ceb);
	we_t = GPU_SHA256_EXPAND(wc_t, w7_t, wf_t, we_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, c, d, e, f, g, h, a, b, we_t, 0xbef9a3f7);
	wf_t = GPU_SHA256_EXPAND(wd_t, w8_t, w0_t, wf_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, 0xc67178f2);

	digest[0] += a;
	digest[1] += b;
	digest[2] += c;
	digest[3] += d;
	digest[4] += e;
	digest[5] += f;
	digest[6] += g;
	digest[7] += h;
}
void _SHA256_process(uint8_t* pt, uint64_t ptLen, SHA256_INFO* info) {
	uint64_t pt_index = 0;
	while ((ptLen + info->lastLen) >= GPU_SHA256_BLOCK) {
		for (int i = info->lastLen; i < (GPU_SHA256_BLOCK - info->lastLen); i++) {
			info->BUF[i] = pt[i + pt_index];
		}
		_SHA256_core((uint32_t*)info->BUF, info->digest);
		ptLen -= (GPU_SHA256_BLOCK - info->lastLen);
		info->ptLen += (GPU_SHA256_BLOCK - info->lastLen);
		pt_index += (GPU_SHA256_BLOCK - info->lastLen);
		info->lastLen = 0;
	}
	for (int i = 0; i < ptLen; i++)
		info->BUF[i + info->lastLen] = pt[i + pt_index];
	info->lastLen += ptLen;
}
void _SHA256_final(SHA256_INFO* info, uint8_t* out) {
	uint64_t r = (info->lastLen) % GPU_SHA256_BLOCK;
	info->BUF[r++] = 0x80;
	if (r >= GPU_SHA256_BLOCK - 8) {
		for (uint64_t i = r; i < GPU_SHA256_BLOCK; i++)
			info->BUF[i] = 0;
		_SHA256_core((uint32_t*)info->BUF, info->digest);
		for (int i = 0; i < GPU_SHA256_BLOCK - 8; i++)
			info->BUF[i] = 0;
	}
	else {
		for (uint64_t i = r; i < GPU_SHA256_BLOCK - 8; i++)
			info->BUF[i] = 0;
	}
	((uint32_t*)info->BUF)[GPU_SHA256_BLOCK / 4 - 2] = GPU_ENDIAN_CHANGE32((info->ptLen + info->lastLen) >> 29);
	((uint32_t*)info->BUF)[GPU_SHA256_BLOCK / 4 - 1] = GPU_ENDIAN_CHANGE32((info->ptLen + info->lastLen) << 3) & 0xffffffff;
	_SHA256_core((uint32_t*)info->BUF, info->digest);
	out[0] = (info->digest[0] >> 24) & 0xff;
	out[1] = (info->digest[0] >> 16) & 0xff;
	out[2] = (info->digest[0] >> 8) & 0xff;
	out[3] = (info->digest[0]) & 0xff;

	out[4] = (info->digest[1] >> 24) & 0xff;
	out[5] = (info->digest[1] >> 16) & 0xff;
	out[6] = (info->digest[1] >> 8) & 0xff;
	out[7] = (info->digest[1]) & 0xff;

	out[8] = (info->digest[2] >> 24) & 0xff;
	out[9] = (info->digest[2] >> 16) & 0xff;
	out[10] = (info->digest[2] >> 8) & 0xff;
	out[11] = (info->digest[2]) & 0xff;

	out[12] = (info->digest[3] >> 24) & 0xff;
	out[13] = (info->digest[3] >> 16) & 0xff;
	out[14] = (info->digest[3] >> 8) & 0xff;
	out[15] = (info->digest[3]) & 0xff;

	out[16] = (info->digest[4] >> 24) & 0xff;
	out[17] = (info->digest[4] >> 16) & 0xff;
	out[18] = (info->digest[4] >> 8) & 0xff;
	out[19] = (info->digest[4]) & 0xff;

	out[20] = (info->digest[5] >> 24) & 0xff;
	out[21] = (info->digest[5] >> 16) & 0xff;
	out[22] = (info->digest[5] >> 8) & 0xff;
	out[23] = (info->digest[5]) & 0xff;

	out[24] = (info->digest[6] >> 24) & 0xff;
	out[25] = (info->digest[6] >> 16) & 0xff;
	out[26] = (info->digest[6] >> 8) & 0xff;
	out[27] = (info->digest[6]) & 0xff;

	out[28] = (info->digest[7] >> 24) & 0xff;
	out[29] = (info->digest[7] >> 16) & 0xff;
	out[30] = (info->digest[7] >> 8) & 0xff;
	out[31] = (info->digest[7]) & 0xff;
}
void _SHA256(uint8_t* pt, uint64_t ptLen, uint8_t* digest) {
	SHA256_INFO info;
	_SHA256_init(&info);
	_SHA256_process(pt, ptLen, &info);
	_SHA256_final(&info, digest);
}
void _SHA256_preCompute_core(uint32_t* input, uint32_t* digest) {
	for (int i = 0; i < 16; i++)
		input[i] = GPU_ENDIAN_CHANGE32(input[i]);

	uint32_t w0_t = input[0];
	uint32_t w1_t = input[1];
	uint32_t w2_t = input[2];
	uint32_t w3_t = input[3];
	uint32_t w4_t = input[4];
	uint32_t w5_t = input[5];
	uint32_t w6_t = input[6];
	uint32_t w7_t = input[7];
	uint32_t w8_t = input[8];
	uint32_t w9_t = input[9];
	uint32_t wa_t = input[10];
	uint32_t wb_t = input[11];
	uint32_t wc_t = input[12];
	uint32_t wd_t = input[13];
	uint32_t we_t = input[14];
	uint32_t wf_t = input[15];


	uint32_t a = 0x6a09e667;
	uint32_t b = 0xbb67ae85;
	uint32_t c = 0x3c6ef372;
	uint32_t d = 0xa54ff53a;
	uint32_t e = 0x510e527f;
	uint32_t f = 0x9b05688c;
	uint32_t g = 0x1f83d9ab;
	uint32_t h = 0x5be0cd19;


	GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, 0x428a2f98);
	GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, 0x71374491);
	GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, 0xb5c0fbcf);
	GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, 0xe9b5dba5);
	GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, 0x3956c25b);
	GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, 0x59f111f1);
	GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, 0x923f82a4);
	GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, 0xab1c5ed5);
	GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, 0xd807aa98);
	GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, 0x12835b01);
	GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, 0x243185be);
	GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, 0x550c7dc3);
	GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, 0x72be5d74);
	GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, 0x80deb1fe);
	GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, c, d, e, f, g, h, a, b, we_t, 0x9bdc06a7);
	GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, 0xc19bf174);

	w0_t = GPU_SHA256_EXPAND(we_t, w9_t, w1_t, w0_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, 0xe49b69c1);
	w1_t = GPU_SHA256_EXPAND(wf_t, wa_t, w2_t, w1_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, 0xefbe4786);
	w2_t = GPU_SHA256_EXPAND(w0_t, wb_t, w3_t, w2_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, 0x0fc19dc6);
	w3_t = GPU_SHA256_EXPAND(w1_t, wc_t, w4_t, w3_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, 0x240ca1cc);
	w4_t = GPU_SHA256_EXPAND(w2_t, wd_t, w5_t, w4_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, 0x2de92c6f);
	w5_t = GPU_SHA256_EXPAND(w3_t, we_t, w6_t, w5_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, 0x4a7484aa);
	w6_t = GPU_SHA256_EXPAND(w4_t, wf_t, w7_t, w6_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, 0x5cb0a9dc);
	w7_t = GPU_SHA256_EXPAND(w5_t, w0_t, w8_t, w7_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, 0x76f988da);
	w8_t = GPU_SHA256_EXPAND(w6_t, w1_t, w9_t, w8_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, 0x983e5152);
	w9_t = GPU_SHA256_EXPAND(w7_t, w2_t, wa_t, w9_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, 0xa831c66d);
	wa_t = GPU_SHA256_EXPAND(w8_t, w3_t, wb_t, wa_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, 0xb00327c8);
	wb_t = GPU_SHA256_EXPAND(w9_t, w4_t, wc_t, wb_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, 0xbf597fc7);
	wc_t = GPU_SHA256_EXPAND(wa_t, w5_t, wd_t, wc_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, 0xc6e00bf3);
	wd_t = GPU_SHA256_EXPAND(wb_t, w6_t, we_t, wd_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, 0xd5a79147);
	we_t = GPU_SHA256_EXPAND(wc_t, w7_t, wf_t, we_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, c, d, e, f, g, h, a, b, we_t, 0x06ca6351);
	wf_t = GPU_SHA256_EXPAND(wd_t, w8_t, w0_t, wf_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, 0x14292967);

	w0_t = GPU_SHA256_EXPAND(we_t, w9_t, w1_t, w0_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, 0x27b70a85);
	w1_t = GPU_SHA256_EXPAND(wf_t, wa_t, w2_t, w1_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, 0x2e1b2138);
	w2_t = GPU_SHA256_EXPAND(w0_t, wb_t, w3_t, w2_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, 0x4d2c6dfc);
	w3_t = GPU_SHA256_EXPAND(w1_t, wc_t, w4_t, w3_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, 0x53380d13);
	w4_t = GPU_SHA256_EXPAND(w2_t, wd_t, w5_t, w4_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, 0x650a7354);
	w5_t = GPU_SHA256_EXPAND(w3_t, we_t, w6_t, w5_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, 0x766a0abb);
	w6_t = GPU_SHA256_EXPAND(w4_t, wf_t, w7_t, w6_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, 0x81c2c92e);
	w7_t = GPU_SHA256_EXPAND(w5_t, w0_t, w8_t, w7_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, 0x92722c85);
	w8_t = GPU_SHA256_EXPAND(w6_t, w1_t, w9_t, w8_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, 0xa2bfe8a1);
	w9_t = GPU_SHA256_EXPAND(w7_t, w2_t, wa_t, w9_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, 0xa81a664b);
	wa_t = GPU_SHA256_EXPAND(w8_t, w3_t, wb_t, wa_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, 0xc24b8b70);
	wb_t = GPU_SHA256_EXPAND(w9_t, w4_t, wc_t, wb_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, 0xc76c51a3);
	wc_t = GPU_SHA256_EXPAND(wa_t, w5_t, wd_t, wc_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, 0xd192e819);
	wd_t = GPU_SHA256_EXPAND(wb_t, w6_t, we_t, wd_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, 0xd6990624);
	we_t = GPU_SHA256_EXPAND(wc_t, w7_t, wf_t, we_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, c, d, e, f, g, h, a, b, we_t, 0xf40e3585);
	wf_t = GPU_SHA256_EXPAND(wd_t, w8_t, w0_t, wf_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, 0x106aa070);

	w0_t = GPU_SHA256_EXPAND(we_t, w9_t, w1_t, w0_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, 0x19a4c116);
	w1_t = GPU_SHA256_EXPAND(wf_t, wa_t, w2_t, w1_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, 0x1e376c08);
	w2_t = GPU_SHA256_EXPAND(w0_t, wb_t, w3_t, w2_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, 0x2748774c);
	w3_t = GPU_SHA256_EXPAND(w1_t, wc_t, w4_t, w3_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, 0x34b0bcb5);
	w4_t = GPU_SHA256_EXPAND(w2_t, wd_t, w5_t, w4_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, 0x391c0cb3);
	w5_t = GPU_SHA256_EXPAND(w3_t, we_t, w6_t, w5_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, 0x4ed8aa4a);
	w6_t = GPU_SHA256_EXPAND(w4_t, wf_t, w7_t, w6_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, 0x5b9cca4f);
	w7_t = GPU_SHA256_EXPAND(w5_t, w0_t, w8_t, w7_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, 0x682e6ff3);
	w8_t = GPU_SHA256_EXPAND(w6_t, w1_t, w9_t, w8_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, 0x748f82ee);
	w9_t = GPU_SHA256_EXPAND(w7_t, w2_t, wa_t, w9_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, 0x78a5636f);
	wa_t = GPU_SHA256_EXPAND(w8_t, w3_t, wb_t, wa_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, 0x84c87814);
	wb_t = GPU_SHA256_EXPAND(w9_t, w4_t, wc_t, wb_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, 0x8cc70208);
	wc_t = GPU_SHA256_EXPAND(wa_t, w5_t, wd_t, wc_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, 0x90befffa);
	wd_t = GPU_SHA256_EXPAND(wb_t, w6_t, we_t, wd_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, 0xa4506ceb);
	we_t = GPU_SHA256_EXPAND(wc_t, w7_t, wf_t, we_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, c, d, e, f, g, h, a, b, we_t, 0xbef9a3f7);
	wf_t = GPU_SHA256_EXPAND(wd_t, w8_t, w0_t, wf_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, 0xc67178f2);

	digest[0] = a + 0x6a09e667;
	digest[1] = b + 0xbb67ae85;
	digest[2] = c + 0x3c6ef372;
	digest[3] = d + 0xa54ff53a;
	digest[4] = e + 0x510e527f;
	digest[5] = f + 0x9b05688c;
	digest[6] = g + 0x1f83d9ab;
	digest[7] = h + 0x5be0cd19;
}
void _SHA256_salt_compute_final(SHA256_INFO* info, uint32_t* out) {
	uint64_t r = (info->lastLen) % GPU_SHA256_BLOCK;
	info->BUF[r++] = 0x80;
	if (r >= GPU_SHA256_BLOCK - 8) {
		for (uint64_t i = r; i < GPU_SHA256_BLOCK; i++)
			info->BUF[i] = 0;
		_SHA256_core((uint32_t*)info->BUF, info->digest);
		for (int i = 0; i < GPU_SHA256_BLOCK - 8; i++)
			info->BUF[i] = 0;
	}
	else {
		for (uint64_t i = r; i < GPU_SHA256_BLOCK - 8; i++)
			info->BUF[i] = 0;
	}
	((uint32_t*)info->BUF)[GPU_SHA256_BLOCK / 4 - 2] = GPU_ENDIAN_CHANGE32((info->ptLen + info->lastLen) >> 29);
	((uint32_t*)info->BUF)[GPU_SHA256_BLOCK / 4 - 1] = GPU_ENDIAN_CHANGE32((info->ptLen + info->lastLen) << 3) & 0xffffffff;
	_SHA256_core((uint32_t*)info->BUF, info->digest);

	out[0] = info->digest[0];
	out[1] = info->digest[1];
	out[2] = info->digest[2];
	out[3] = info->digest[3];
	out[4] = info->digest[4];
	out[5] = info->digest[5];
	out[6] = info->digest[6];
	out[7] = info->digest[7];
}
void _PBKDF2_HMAC_SHA256_precompute(uint8_t* pt, uint8_t ptLen, PBKDF2_HMAC_SHA256_INFO* info) {
	uint8_t K1[GPU_SHA256_BLOCK];
	uint8_t K2[GPU_SHA256_BLOCK];

	for (int i = 0; i < ptLen; i++) {
		K1[i] = 0x36 ^ pt[i];
		K2[i] = 0x5c ^ pt[i];
	}
	for (int i = ptLen; i < GPU_SHA256_BLOCK; i++) {
		K1[i] = 0x36;
		K2[i] = 0x5c;
	}
	_SHA256_preCompute_core((uint32_t*)K1, info->IPAD);
	_SHA256_preCompute_core((uint32_t*)K2, info->OPAD);
}
void _PBKDF2_HMAC_SHA256_salt_compute(uint8_t* salt, uint64_t saLen, uint32_t integer, PBKDF2_HMAC_SHA256_INFO* INFO, uint32_t* out) {
	SHA256_INFO info;
	uint8_t temp[4] = { (integer >> 24) & 0xff, (integer >> 16) & 0xff, (integer >> 8) & 0xff, (integer & 0xff) };
	info.digest[0] = INFO->IPAD[0];
	info.digest[1] = INFO->IPAD[1];
	info.digest[2] = INFO->IPAD[2];
	info.digest[3] = INFO->IPAD[3];
	info.digest[4] = INFO->IPAD[4];
	info.digest[5] = INFO->IPAD[5];
	info.digest[6] = INFO->IPAD[6];
	info.digest[7] = INFO->IPAD[7];
	info.ptLen = 64;
	info.lastLen = 0;
	_SHA256_process(salt, saLen, &info);
	_SHA256_process(temp, 4, &info);
	_SHA256_salt_compute_final(&info, out);
}
void _PBKDF2_HMAC_SHA256_core(uint32_t* _prestate, uint32_t* digest, uint32_t* in) {

	uint32_t w0_t = in[0];
	uint32_t w1_t = in[1];
	uint32_t w2_t = in[2];
	uint32_t w3_t = in[3];
	uint32_t w4_t = in[4];
	uint32_t w5_t = in[5];
	uint32_t w6_t = in[6];
	uint32_t w7_t = in[7];
	uint32_t w8_t = 0x80000000;
	uint32_t w9_t = 0;
	uint32_t wa_t = 0;
	uint32_t wb_t = 0;
	uint32_t wc_t = 0;
	uint32_t wd_t = 0;
	uint32_t we_t = 0;
	uint32_t wf_t = (64 + 32) << 3;

	uint32_t a = _prestate[0];
	uint32_t b = _prestate[1];
	uint32_t c = _prestate[2];
	uint32_t d = _prestate[3];
	uint32_t e = _prestate[4];
	uint32_t f = _prestate[5];
	uint32_t g = _prestate[6];
	uint32_t h = _prestate[7];

	GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, 0x428a2f98);
	GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, 0x71374491);
	GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, 0xb5c0fbcf);
	GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, 0xe9b5dba5);
	GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, 0x3956c25b);
	GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, 0x59f111f1);
	GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, 0x923f82a4);
	GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, 0xab1c5ed5);
	GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, 0xd807aa98);
	GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, 0x12835b01);
	GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, 0x243185be);
	GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, 0x550c7dc3);
	GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, 0x72be5d74);
	GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, 0x80deb1fe);
	GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, c, d, e, f, g, h, a, b, we_t, 0x9bdc06a7);
	GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, 0xc19bf174);

	w0_t = GPU_SHA256_EXPAND(we_t, w9_t, w1_t, w0_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, 0xe49b69c1);
	w1_t = GPU_SHA256_EXPAND(wf_t, wa_t, w2_t, w1_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, 0xefbe4786);
	w2_t = GPU_SHA256_EXPAND(w0_t, wb_t, w3_t, w2_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, 0x0fc19dc6);
	w3_t = GPU_SHA256_EXPAND(w1_t, wc_t, w4_t, w3_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, 0x240ca1cc);
	w4_t = GPU_SHA256_EXPAND(w2_t, wd_t, w5_t, w4_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, 0x2de92c6f);
	w5_t = GPU_SHA256_EXPAND(w3_t, we_t, w6_t, w5_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, 0x4a7484aa);
	w6_t = GPU_SHA256_EXPAND(w4_t, wf_t, w7_t, w6_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, 0x5cb0a9dc);
	w7_t = GPU_SHA256_EXPAND(w5_t, w0_t, w8_t, w7_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, 0x76f988da);
	w8_t = GPU_SHA256_EXPAND(w6_t, w1_t, w9_t, w8_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, 0x983e5152);
	w9_t = GPU_SHA256_EXPAND(w7_t, w2_t, wa_t, w9_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, 0xa831c66d);
	wa_t = GPU_SHA256_EXPAND(w8_t, w3_t, wb_t, wa_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, 0xb00327c8);
	wb_t = GPU_SHA256_EXPAND(w9_t, w4_t, wc_t, wb_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, 0xbf597fc7);
	wc_t = GPU_SHA256_EXPAND(wa_t, w5_t, wd_t, wc_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, 0xc6e00bf3);
	wd_t = GPU_SHA256_EXPAND(wb_t, w6_t, we_t, wd_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, 0xd5a79147);
	we_t = GPU_SHA256_EXPAND(wc_t, w7_t, wf_t, we_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, c, d, e, f, g, h, a, b, we_t, 0x06ca6351);
	wf_t = GPU_SHA256_EXPAND(wd_t, w8_t, w0_t, wf_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, 0x14292967);

	w0_t = GPU_SHA256_EXPAND(we_t, w9_t, w1_t, w0_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, 0x27b70a85);
	w1_t = GPU_SHA256_EXPAND(wf_t, wa_t, w2_t, w1_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, 0x2e1b2138);
	w2_t = GPU_SHA256_EXPAND(w0_t, wb_t, w3_t, w2_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, 0x4d2c6dfc);
	w3_t = GPU_SHA256_EXPAND(w1_t, wc_t, w4_t, w3_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, 0x53380d13);
	w4_t = GPU_SHA256_EXPAND(w2_t, wd_t, w5_t, w4_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, 0x650a7354);
	w5_t = GPU_SHA256_EXPAND(w3_t, we_t, w6_t, w5_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, 0x766a0abb);
	w6_t = GPU_SHA256_EXPAND(w4_t, wf_t, w7_t, w6_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, 0x81c2c92e);
	w7_t = GPU_SHA256_EXPAND(w5_t, w0_t, w8_t, w7_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, 0x92722c85);
	w8_t = GPU_SHA256_EXPAND(w6_t, w1_t, w9_t, w8_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, 0xa2bfe8a1);
	w9_t = GPU_SHA256_EXPAND(w7_t, w2_t, wa_t, w9_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, 0xa81a664b);
	wa_t = GPU_SHA256_EXPAND(w8_t, w3_t, wb_t, wa_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, 0xc24b8b70);
	wb_t = GPU_SHA256_EXPAND(w9_t, w4_t, wc_t, wb_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, 0xc76c51a3);
	wc_t = GPU_SHA256_EXPAND(wa_t, w5_t, wd_t, wc_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, 0xd192e819);
	wd_t = GPU_SHA256_EXPAND(wb_t, w6_t, we_t, wd_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, 0xd6990624);
	we_t = GPU_SHA256_EXPAND(wc_t, w7_t, wf_t, we_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, c, d, e, f, g, h, a, b, we_t, 0xf40e3585);
	wf_t = GPU_SHA256_EXPAND(wd_t, w8_t, w0_t, wf_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, 0x106aa070);

	w0_t = GPU_SHA256_EXPAND(we_t, w9_t, w1_t, w0_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, 0x19a4c116);
	w1_t = GPU_SHA256_EXPAND(wf_t, wa_t, w2_t, w1_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, 0x1e376c08);
	w2_t = GPU_SHA256_EXPAND(w0_t, wb_t, w3_t, w2_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, 0x2748774c);
	w3_t = GPU_SHA256_EXPAND(w1_t, wc_t, w4_t, w3_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, 0x34b0bcb5);
	w4_t = GPU_SHA256_EXPAND(w2_t, wd_t, w5_t, w4_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, 0x391c0cb3);
	w5_t = GPU_SHA256_EXPAND(w3_t, we_t, w6_t, w5_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, 0x4ed8aa4a);
	w6_t = GPU_SHA256_EXPAND(w4_t, wf_t, w7_t, w6_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, 0x5b9cca4f);
	w7_t = GPU_SHA256_EXPAND(w5_t, w0_t, w8_t, w7_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, 0x682e6ff3);
	w8_t = GPU_SHA256_EXPAND(w6_t, w1_t, w9_t, w8_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, 0x748f82ee);
	w9_t = GPU_SHA256_EXPAND(w7_t, w2_t, wa_t, w9_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, 0x78a5636f);
	wa_t = GPU_SHA256_EXPAND(w8_t, w3_t, wb_t, wa_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, 0x84c87814);
	wb_t = GPU_SHA256_EXPAND(w9_t, w4_t, wc_t, wb_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, 0x8cc70208);
	wc_t = GPU_SHA256_EXPAND(wa_t, w5_t, wd_t, wc_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, 0x90befffa);
	wd_t = GPU_SHA256_EXPAND(wb_t, w6_t, we_t, wd_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, 0xa4506ceb);
	we_t = GPU_SHA256_EXPAND(wc_t, w7_t, wf_t, we_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, c, d, e, f, g, h, a, b, we_t, 0xbef9a3f7);
	wf_t = GPU_SHA256_EXPAND(wd_t, w8_t, w0_t, wf_t); GPU_SHA256_STEP(GPU_SHA256_F0o, GPU_SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, 0xc67178f2);

	digest[0] = _prestate[0] + a;
	digest[1] = _prestate[1] + b;
	digest[2] = _prestate[2] + c;
	digest[3] = _prestate[3] + d;
	digest[4] = _prestate[4] + e;
	digest[5] = _prestate[5] + f;
	digest[6] = _prestate[6] + g;
	digest[7] = _prestate[7] + h;
}
void PBKDF2_HMAC_SHA256(uint8_t* pt, size_t ptLen, uint8_t* salt, size_t saLen, uint32_t* dk, uint32_t dkLen, size_t iter) {
	uint8_t buf[GPU_SHA256_BLOCK];
	uint32_t _first[8];
	uint32_t _second[8];
	uint32_t temp[8];
	PBKDF2_HMAC_SHA256_INFO info;
	uint32_t _TkLen = dkLen / GPU_SHA256_DIGEST;
	if (dkLen % GPU_SHA256_DIGEST != 0) { _TkLen++; }


	if (ptLen > GPU_SHA256_BLOCK) {
		_SHA256(pt, ptLen, buf);
		_PBKDF2_HMAC_SHA256_precompute(buf, GPU_SHA256_DIGEST, &info);
		info.ptLen = GPU_SHA256_DIGEST;
	}
	else {
		_PBKDF2_HMAC_SHA256_precompute(pt, ptLen, &info);
		info.ptLen = ptLen;
	}
	for (uint32_t i = 0; i < _TkLen; i++) {
		_PBKDF2_HMAC_SHA256_salt_compute(salt, saLen, i + 1, &info, _first);
		_PBKDF2_HMAC_SHA256_core(info.OPAD, _second, _first);
		for (int j = 0; j < 8; j++)
			temp[j] = _second[j];


		for (int k = 1; k < iter; k++) {
			_PBKDF2_HMAC_SHA256_core(info.IPAD, _first, _second);
			_PBKDF2_HMAC_SHA256_core(info.OPAD, _second, _first);
			for (int x = 0; x < 8; x++)
				temp[x] ^= _second[x];
		}
		for (int z = 0; z < 8; z++) {
			dk[8 * i + z] = temp[z];
		}
	}
}


#define R(a,b) (((a) << (b)) | ((a) >> (32 - (b))))
static void salsa208_word_specification(uint32_t inout[16])
{
	int i;
	uint32_t x[16];
	memcpy(x, inout, sizeof(x));
	for (i = 8; i > 0; i -= 2) {
		x[4] ^= R(x[0] + x[12], 7);
		x[8] ^= R(x[4] + x[0], 9);
		x[12] ^= R(x[8] + x[4], 13);
		x[0] ^= R(x[12] + x[8], 18);
		x[9] ^= R(x[5] + x[1], 7);
		x[13] ^= R(x[9] + x[5], 9);
		x[1] ^= R(x[13] + x[9], 13);
		x[5] ^= R(x[1] + x[13], 18);
		x[14] ^= R(x[10] + x[6], 7);
		x[2] ^= R(x[14] + x[10], 9);
		x[6] ^= R(x[2] + x[14], 13);
		x[10] ^= R(x[6] + x[2], 18);
		x[3] ^= R(x[15] + x[11], 7);
		x[7] ^= R(x[3] + x[15], 9);
		x[11] ^= R(x[7] + x[3], 13);
		x[15] ^= R(x[11] + x[7], 18);
		x[1] ^= R(x[0] + x[3], 7);
		x[2] ^= R(x[1] + x[0], 9);
		x[3] ^= R(x[2] + x[1], 13);
		x[0] ^= R(x[3] + x[2], 18);
		x[6] ^= R(x[5] + x[4], 7);
		x[7] ^= R(x[6] + x[5], 9);
		x[4] ^= R(x[7] + x[6], 13);
		x[5] ^= R(x[4] + x[7], 18);
		x[11] ^= R(x[10] + x[9], 7);
		x[8] ^= R(x[11] + x[10], 9);
		x[9] ^= R(x[8] + x[11], 13);
		x[10] ^= R(x[9] + x[8], 18);
		x[12] ^= R(x[15] + x[14], 7);
		x[13] ^= R(x[12] + x[15], 9);
		x[14] ^= R(x[13] + x[12], 13);
		x[15] ^= R(x[14] + x[13], 18);
	}
	for (i = 0; i < 16; ++i)
		inout[i] += x[i];
	memset(x, 0, sizeof(uint32_t) * 16);
}
static void scryptBlockMix(uint32_t* B_, uint32_t* B, uint64_t r)
{
	uint64_t i, j;
	uint32_t X[16], * pB;

	memcpy(X, B + (r * 2 - 1) * 16, sizeof(X));
	pB = B;
	for (i = 0; i < r * 2; i++) {
		for (j = 0; j < 16; j++)
			X[j] ^= *pB++;
		salsa208_word_specification(X);
		memcpy(B_ + (i / 2 + (i & 1) * r) * 16, X, sizeof(X));
	}
	memset(X, 0, sizeof(uint32_t) * 16);
}
static void scryptROMix(unsigned char* B, uint64_t r, uint64_t N,
	uint32_t* X, uint32_t* T, uint32_t* V)
{
	unsigned char* pB;
	uint32_t* pV;
	uint64_t i, k;
	uint64_t cycle0 = 0;
	uint64_t cycle1 = 0;
	/* Convert from little endian input */
	for (pV = V, i = 0, pB = B; i < 32 * r; i++, pV++) {
		*pV = *pB++;
		*pV |= *pB++ << 8;
		*pV |= *pB++ << 16;
		*pV |= (uint32_t)*pB++ << 24;
	}
	for (i = 1; i < N; i++, pV += 32 * r)
		scryptBlockMix(pV, pV - 32 * r, r);
	scryptBlockMix(X, V + (N - 1) * 32 * r, r);

	for (i = 0; i < N; i++) {
		uint32_t j;
		j = X[16 * (2 * r - 1)] % N;
		pV = V + 32 * r * j;
		for (k = 0; k < 32 * r; k++)
			T[k] = X[k] ^ *pV++;
		scryptBlockMix(X, T, r);
	}


	/* Convert output to little endian */
	for (i = 0, pB = B; i < 32 * r; i++) {
		uint32_t xtmp = X[i];
		*pB++ = xtmp & 0xff;
		*pB++ = (xtmp >> 8) & 0xff;
		*pB++ = (xtmp >> 16) & 0xff;
		*pB++ = (xtmp >> 24) & 0xff;
	}
}

int EVP_PBE_scrypt(uint8_t* pass, size_t passlen, uint8_t* salt, size_t saltlen, uint64_t N, uint64_t r, uint64_t p, uint8_t* key, size_t keylen) {
	uint64_t i, Blen, Vlen;
	uint32_t* X = NULL;
	uint32_t* T = NULL;
	uint32_t* V = NULL;
	uint8_t* B = NULL;
	uint64_t cycle0 = 0;
	uint64_t cycle1 = 0;
	uint64_t result = 0;
	Blen = p * 128 * r;
	Vlen = 32 * r * (N + 2) * sizeof(uint32_t);
	B = (uint8_t*)malloc(Blen + Vlen);
	X = (uint32_t*)(B + Blen);
	T = X + 32 * r;
	V = T + 32 * r;

	cycle0 = cpucycles();
	PBKDF2_HMAC_SHA256(pass, passlen, salt, saltlen, (uint32_t*)B, Blen, 1);
	cycle1 = cpucycles();
	result += cycle1 - cycle0;

	for (i = 0; i < p; i++) {
		cycle0 = cpucycles();
		scryptROMix(B + 128 * r * i, r, N, X, T, V);
		cycle1 = cpucycles();
		result += cycle1 - cycle0;
	}

	cycle0 = cpucycles();
	PBKDF2_HMAC_SHA256(pass, passlen, B, Blen, key, keylen, 1);
	cycle1 = cpucycles();
	result += cycle1 - cycle0;

	printf("[CPU] Performance of Scrypt/sec = %llu\n", (2500000000) / (result));	//사용 하고계신 CPU 성능에 맞게 앞의 숫자 바꿔서 측정하셔야 정확해용
}

int main()
{
	uint32_t dkout[16] = { 0, };
	uint8_t password[8] = { 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64 };
	uint8_t salt[4] = { 0x4e, 0x61, 0x43, 0x6c };
	uint32_t r = 8;
	uint32_t p = 2;															//p가 2일때, p가 4일때의 값
	uint32_t N = 1024;
	uint32_t dklen = 64;
	EVP_PBE_scrypt(password, 8, salt, 4, N, r, p, (uint8_t*)dkout, dklen);

	return 0;
}