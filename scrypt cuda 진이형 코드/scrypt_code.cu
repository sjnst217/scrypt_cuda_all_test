#include "type_origin.cuh"

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

__device__ void _SHA256_init(SHA256_INFO* info) {
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
__device__ void _SHA256_core(uint32_t* input, uint32_t* digest) {
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
__device__ void _SHA256_process(uint8_t* pt, uint64_t ptLen, SHA256_INFO* info) {
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
__device__ void _SHA256_final(SHA256_INFO* info, uint8_t* out) {
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
__device__ void _SHA256(uint8_t* pt, uint64_t ptLen, uint8_t* digest) {
	SHA256_INFO info;
	_SHA256_init(&info);
	_SHA256_process(pt, ptLen, &info);
	_SHA256_final(&info, digest);
}
__device__ void _SHA256_preCompute_core(uint32_t* input, uint32_t* digest) {
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
__device__ void _SHA256_salt_compute_final(SHA256_INFO* info, uint32_t* out) {
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
__device__ void _PBKDF2_HMAC_SHA256_precompute(uint8_t* pt, uint8_t ptLen, PBKDF2_HMAC_SHA256_INFO* info) {
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
__device__ void _PBKDF2_HMAC_SHA256_salt_compute(uint8_t* salt, uint64_t saLen, uint32_t integer, PBKDF2_HMAC_SHA256_INFO* INFO, uint32_t* out) {
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
__device__ void _PBKDF2_HMAC_SHA256_core(uint32_t* _prestate, uint32_t* digest, uint32_t* in) {

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
__device__ void PBKDF2_HMAC_SHA256(uint8_t* pt, size_t ptLen, uint8_t* salt, size_t saLen, uint8_t* dkout, size_t dkLen, size_t iter) {
	uint8_t buf[GPU_SHA256_BLOCK];
	uint32_t _first[8];
	uint32_t _second[8];
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
		for (int z = 0; z < 8; z++) {
			dkout[4 * z + 0] = (_second[z] >> 24) & 0xff;
			dkout[4 * z + 1] = (_second[z] >> 16) & 0xff;
			dkout[4 * z + 2] = (_second[z] >> 8) & 0xff;
			dkout[4 * z + 3] = (_second[z] >> 0) & 0xff;
		}
		dkout += 32;
	}
}


__device__ void salsa208_word_specification(uint32_t inout[16])
{
	int i;
	uint32_t x[16];
	memcpy(x, inout, sizeof(uint32_t) * 16);
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
}
__device__ void scryptBlockMix(uint32_t* B_, uint32_t* B, uint64_t r) // B_�� ���� B�� ���� BlockMix���� ���� ��������
{
	uint64_t i, j;
	uint32_t X[16], * pB;

	memcpy(X, B + (r * 2 - 1) * 16, sizeof(uint32_t) * 16);
	pB = B;
	for (i = 0; i < r * 2; i++) {
		for (j = 0; j < 16; j++)
			X[j] ^= *pB++;
		salsa208_word_specification(X);
		memcpy(B_ + (i / 2 + (i & 1) * r) * 16, X, sizeof(X));
	}
} 
__device__ void scryptROMix(unsigned char* B, uint64_t r, uint64_t N, uint32_t* X, uint32_t* T, uint32_t* V)
{
	unsigned char* pB;
	uint32_t* pV;
	uint64_t i, k;
	uint64_t cycle0 = 0;
	uint64_t cycle1 = 0;
	/* Convert from little endian input */
	for (pV = V, i = 0, pB = B; i < 32 * r; i++, pV++) {	//unsigned int ���� pV���ٰ� unsigned char ���� pB�� ����־��ֱ�
		*pV = *pB++;										//-> �̷��� 128 * r �� �ƴ϶� 32 * r �� �ٲ� �� �ִ� -> �ݺ� Ƚ���� ���� �� ����
		*pV |= *pB++ << 8;									// �ᱹ �� ó�� V�� ����� �ִ� �ڵ�
		*pV |= *pB++ << 16;
		*pV |= (uint32_t)*pB++ << 24;
	}
	for (i = 1; i < N; i++, pV += 32 * r)					//V�� N - 1 ���� �������ִ� �ڵ�
		scryptBlockMix(pV, pV - 32 * r, r);
	scryptBlockMix(X, V + (N - 1) * 32 * r, r);

	for (i = 0; i < N; i++) {
		uint32_t j;						//mod������ ���ؼ� ���° V���� ����� �� �������ֱ� ���� ����
		j = X[16 * (2 * r - 1)] % N;	//mod������ ���ְ�
		pV = V + 32 * r * j;			//pV�� ���� V�� j��° �� �־��ְ�
		for (k = 0; k < 32 * r; k++)
			T[k] = X[k] ^ *pV++;		//T�� ���� X�� pV�� �� XOR����
		scryptBlockMix(X, T, r);		//X�� ���� T�� ���� blockMix�ؼ� ����
	}


	/* Convert output to little endian */
	for (i = 0, pB = B; i < 32 * r; i++) { //pB�� ������ ���� ������� ����־��ֱ� ���ؼ� endian ��ȯ�� ���ؼ� ����
		uint32_t xtmp = X[i];
		*pB++ = xtmp & 0xff;
		*pB++ = (xtmp >> 8) & 0xff;
		*pB++ = (xtmp >> 16) & 0xff;
		*pB++ = (xtmp >> 24) & 0xff;
	}
}


//				������� ��ü �Ҵ� block, ��ü �Ҵ� password, password�� ����, ��ü �Ҵ� salt, salt�� ����, N, r, p, ��ü �Ҵ� key, key�� ����
__global__ void GPU_scrypt(uint8_t* B, uint8_t* pass, size_t passlen, uint8_t* salt, size_t saltlen, uint64_t N, uint64_t r, uint64_t p, uint8_t* key, size_t keylen) 
{
	uint64_t data_index = 0;											//���� �������� block(data)�� ���� index
	uint64_t store_index = 0;										//���� �������� key�� ������ �� ����ϱ� ���� index
	uint64_t i, Blen, Vlen, j;
	uint64_t total_len;
	Blen = p * 128 * r;													//block ��ü�� ����
	Vlen = 32 * r * (N + 2) * sizeof(uint32_t);					//���ο��� ����ϴ� Vector�� ����
	total_len = Blen + Vlen;											//���Ǵ� ��� ������ ��
	data_index = (blockDim.x * blockIdx.x) + threadIdx.x;	//������ ������ ��ȣ�� ���ؼ�
	data_index = data_index * total_len;							//��ü data ���̿� �����ִ� ������ ���� �������� block�� ���� index�� ������
	store_index = (blockDim.x * blockIdx.x) + threadIdx.x;	//������ ������ ��ȣ�� ���ؼ�
	store_index = store_index * keylen;							//��ü key ���̿� �����ִ� ������ ���� �������� key�� ���� index�� ������

	uint32_t* X = NULL;												//���� �����忡�� ���� X(ROMix�Լ��� �ʱ� block)�� ���� �����ϱ� ���� ����
	uint32_t* T = NULL;												//���� �����忡�� ���� T(ROMix�Լ��� �߰� ��� block (X XOR V_j ���� �ֵ�))�� ���� �����ϱ� ���� ����
	uint32_t* V = NULL;												//���� �����忡�� ���� V(Vector)�� ���� �����ϱ� ���� ����
	X = (uint32_t*)(B + Blen + data_index);
	T = X + 32 * r;
	V = T + 32 * r;

	PBKDF2_HMAC_SHA256(pass + (passlen * (blockDim.x * blockIdx.x + threadIdx.x)), passlen, salt + (saltlen * (blockDim.x * blockIdx.x + threadIdx.x)), saltlen, B + data_index, Blen, 1);
	for (i = 0; i < p; i++)	
		scryptROMix(B + data_index + 128 * r * i, r, N, X, T, V);
	PBKDF2_HMAC_SHA256(pass + (passlen * (blockDim.x * blockIdx.x + threadIdx.x)), passlen, B + data_index, Blen, key + store_index, keylen, 1);
}
void performance_test_scrypt(uint32_t blocksize, uint32_t threadsize) {
	cudaError_t err;
	cudaEvent_t start, stop;
	uint8_t password[8] = { 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64 };
	uint8_t salt[4] = { 0x4e, 0x61, 0x43, 0x6c };
	uint8_t* cpu_key = (uint8_t*)malloc(blocksize * threadsize * 64); //scrypt ���� ���� key����� 
	if (cpu_key == NULL)
		return;

	uint8_t* gpu_pass = NULL;										//gpu ���ο����� password
	uint8_t* gpu_salt = NULL;										//gpu ���ο����� salt
	uint8_t* gpu_key = NULL;										//gpu ���ο����� key
	uint8_t* gpu_b = NULL;											//gpu ���ο����� ��ü block
	uint64_t Blen = 128 * 2 * 8;									//block ���� (128 * p * r)
	uint64_t Vlen = 32 * 8 * (1024 + 2) * sizeof(uint32_t);			//���ο��� ����ϴ� Vector�� ���� (128 * r * N) ���⿡�� 32�� ������ Vector�� ������ �� uint8_t ���� block�� uint32_t�� �ٲپ �����ϱ� ����, (N + 2)�� �� �� ������ X block �� ������ �����(output) �� ũ�⸦ �Ҵ��ϱ� ���ؼ� �ε�?
	uint64_t total = Blen + Vlen;									//���ο� �Ҵ��� ��ü ũ��
	float elapsed_time_ms = 0.0f;


	cudaMalloc((void**)&gpu_pass, 8 * blocksize * threadsize);			//gpu ��ü password �Ҵ�
	cudaMalloc((void**)&gpu_salt, 4 * blocksize * threadsize);			//gpu ��ü salt �Ҵ�
	cudaMalloc((void**)&gpu_key, 64 * blocksize * threadsize);			//gpu ��ü key �Ҵ�
	err = cudaMalloc((void**)&gpu_b, total * blocksize * threadsize);	//gpu ��ü block �Ҵ� -> ��ü block ũ�⸦ �Ҵ��ؾ� �ϱ� ������ ���Ǵ� ��� block�� ũ�⸦ �����ؼ� �Ҵ��� �־�� �� 
	if (err != cudaSuccess) {
		printf("gpu_b : CUDA error : %s\n", cudaGetErrorString(err));
	}

	cudaEventCreate(&start);
	cudaEventCreate(&stop);
	cudaEventRecord(start, 0);

	for (int i = 0; i < blocksize * threadsize; i++) {
		cudaMemcpy(gpu_pass + (8 * i), password, 8, cudaMemcpyHostToDevice);	//gpu_pass���� ������ �����忡�� ����� ������ password�� �������� -> ��ȯ�ϰ��� �ϴ� �ڵ忡���� 1���� ���ָ� ��
		cudaMemcpy(gpu_salt + (4 * i), salt, 4, cudaMemcpyHostToDevice);		//gpu_salt���� ������ �����忡�� ����� ������ salt�� �������� -> ���� ����
		password[7] = (i + 1) &0xff;											//�� �� �ݺ� ������ password�� ��ȯ�����ֱ� ���� -> ��ȯ�ϰ��� �ϴ� �ڵ忡���� �����൵ ��
		salt[3] = (i + 2) &0xff;												//�� �� �ݺ� ������ salt�� ��ȯ�����ֱ� ���� -> ���� ����
	}

	for (int i = 0; i < 1; i++) {
		GPU_scrypt << <blocksize, threadsize >> > (gpu_b, gpu_pass, 8, gpu_salt, 4, 1024, 8, 2, gpu_key, 64);	// ������� ��ü �Ҵ� block, ��ü �Ҵ� password, password�� ����, ��ü �Ҵ� salt, salt�� ����, N, r, p, ��ü �Ҵ� key, key�� ����
		cudaMemcpy(cpu_key, gpu_key, 64 * blocksize * threadsize, cudaMemcpyDeviceToHost);						// ������ ��ģ gpu�� ��ü key�� cpu�� ����
	}

	cudaEventRecord(stop, 0);
	cudaDeviceSynchronize();
	cudaEventSynchronize(start);
	cudaEventSynchronize(stop);
	cudaEventElapsedTime(&elapsed_time_ms, start, stop);
	printf("%4.2f\n", elapsed_time_ms);
	printf("blocksize: %d, threadsize: %d, scrypt/s: %4.2f\n", blocksize, threadsize, blocksize * threadsize * (1000 / elapsed_time_ms));

	cudaFree(gpu_pass);
	cudaFree(gpu_salt);
	cudaFree(gpu_b);
	cudaFree(gpu_key);
	free(cpu_key);
}

int main() {
	performance_test_scrypt(2, 16);
	performance_test_scrypt(16, 2);

	performance_test_scrypt(2, 32);
	performance_test_scrypt(32, 2);

	performance_test_scrypt(2, 64);
	performance_test_scrypt(64, 2);

	performance_test_scrypt(2, 128);
	performance_test_scrypt(128, 2);

	performance_test_scrypt(2, 256);
	performance_test_scrypt(256, 2);



}