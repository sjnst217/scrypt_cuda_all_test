#include "type.cuh"

typedef struct
{
    uint32_t digest[8];
    uint64_t ptLen;
    uint8_t BUF[GPU_SHA256_BLOCK];
    uint32_t lastLen;
}SHA256_INFO;

typedef struct
{
    uint32_t IPAD[8];
    uint32_t OPAD[8];
    uint64_t ptLen;
}PBKDF2_HMAC_SHA256_INFO;

#define GPU_ENDIAN_CHANGE32(X)      ((GPU_rotl32((X),  8) & 0x00ff00ff) | (GPU_rotl32((X), 24) & 0xff00ff00))

__host__ __device__ void _SHA256_init(SHA256_INFO* info)
{
    info->digest[0] = 0x6a09e667;
    info->digest[1] = 0xbb67ae85;
    info->digest[2] = 0x3c6ef372;
    info->digest[3] = 0xa54ff53a;
    info->digest[4] = 0x510e527f;
    info->digest[5] = 0x9b05688c;
    info->digest[6] = 0x1f83d9ab;
    info->digest[7] = 0x5be0cd19;

    for (int i = 0; i < GPU_SHA256_BLOCK; i++)
    {
        info->BUF[i] = 0;
    }
    info->ptLen = 0, info->lastLen = 0;
}
__host__ __device__ void _SHA256_core(uint32_t* input, uint32_t* digest)
{
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
__host__ __device__ void _SHA256_process(uint8_t* pt, uint64_t ptLen, SHA256_INFO* info)
{
    uint64_t pt_index = 0;
    while ((ptLen + info->lastLen) >= GPU_SHA256_BLOCK)
    {
        for (int i = info->lastLen; i < (GPU_SHA256_BLOCK - info->lastLen); i++)
        {
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

__host__ __device__ void _SHA256_process_coalesced(uint8_t* pt, uint64_t ptLen, SHA256_INFO* info, uint64_t p, uint64_t num_of_scrypt)
{
    uint64_t pt_index = 0;              //pt의 시작 위치를 찾는 index
    uint64_t us_pt_index = 0;           //총 몇 번의 sha256_core를 이용했는지 확인하기 위한 index

    uint64_t us_coalesced_index = 0;    //다음 pt의 시작 위치를 얻기 위한 index
    uint64_t us_ptLen = 0;              //ptLen에서 몇 번의 sha256_core를 이용하면 다음 coalesced 정렬된 위치를 알기 위한 index

    us_ptLen = ptLen / p;               //128 * r
    us_ptLen /= GPU_SHA256_BLOCK;       // 2 * r

    while ((ptLen + info->lastLen) >= GPU_SHA256_BLOCK)
    {
        for (int i = info->lastLen; i < (GPU_SHA256_BLOCK - info->lastLen); i++)
        {
            info->BUF[i] = pt[i * us_coalesced_index + pt_index];       // 0 ~ 63번째 처리
            us_coalesced_index += num_of_scrypt * p;                    // 각 값에 알맞게 처리
        }
        _SHA256_core((uint32_t*)info->BUF, info->digest);               //BUF의 값의 sha256결과를 digest에 저장
        ptLen -= (GPU_SHA256_BLOCK - info->lastLen);                    //ptLen -= 64
        info->ptLen += (GPU_SHA256_BLOCK - info->lastLen);              //info->ptLen += 64

        pt_index += us_coalesced_index;                                 //pt_index += 64 * nos * p
        us_pt_index++;                                                  //us_pt_index++

        if ((us_pt_index + 1) % us_ptLen == 0)                          //다음 열로 넘어가게 되면
        {
            pt_index = (us_pt_index + 1) / us_ptLen;                    //pt_index의 값을 열의 번호로 나타내줌
        }

        us_coalesced_index = 0;
        info->lastLen = 0;
    }
    for (int i = 0; i < ptLen; i++)
    {
        info->BUF[i + info->lastLen] = pt[i + us_coalesced_index + pt_index];
        us_coalesced_index += num_of_scrypt * p;
    }
    us_coalesced_index = 0;
    info->lastLen += ptLen;
}

__host__ __device__ void _SHA256_final(SHA256_INFO* info, uint8_t* out)
{
    uint64_t r = (info->lastLen) % GPU_SHA256_BLOCK;
    info->BUF[r++] = 0x80;
    if (r >= GPU_SHA256_BLOCK - 8)
    {
        for (uint64_t i = r; i < GPU_SHA256_BLOCK; i++)
            info->BUF[i] = 0;
        _SHA256_core((uint32_t*)info->BUF, info->digest);
        for (int i = 0; i < GPU_SHA256_BLOCK - 8; i++)
            info->BUF[i] = 0;
    }
    else
    {
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
__host__ __device__ void _SHA256(uint8_t* pt, uint64_t ptLen, uint8_t* digest)
{
    SHA256_INFO info;
    _SHA256_init(&info);
    _SHA256_process(pt, ptLen, &info);
    _SHA256_final(&info, digest);
}
__host__ __device__ void _SHA256_preCompute_core(uint32_t* input, uint32_t* digest)
{
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
__host__ __device__ void _SHA256_salt_compute_final(SHA256_INFO* info, uint32_t* out)
{
    uint64_t r = (info->lastLen) % GPU_SHA256_BLOCK;
    info->BUF[r++] = 0x80;
    if (r >= GPU_SHA256_BLOCK - 8)
    {
        for (uint64_t i = r; i < GPU_SHA256_BLOCK; i++)
            info->BUF[i] = 0;
        _SHA256_core((uint32_t*)info->BUF, info->digest);
        for (int i = 0; i < GPU_SHA256_BLOCK - 8; i++)
            info->BUF[i] = 0;
    }
    else
    {
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

__host__ __device__ void _PBKDF2_HMAC_SHA256_precompute(uint8_t* pt, uint8_t ptLen, PBKDF2_HMAC_SHA256_INFO* info)
{
    uint8_t K1[GPU_SHA256_BLOCK];
    uint8_t K2[GPU_SHA256_BLOCK];

    for (int i = 0; i < ptLen; i++)
    {
        K1[i] = 0x36 ^ pt[i];
        K2[i] = 0x5c ^ pt[i];
    }
    for (int i = ptLen; i < GPU_SHA256_BLOCK; i++)
    {
        K1[i] = 0x36;
        K2[i] = 0x5c;
    }
    _SHA256_preCompute_core((uint32_t*)K1, info->IPAD);
    _SHA256_preCompute_core((uint32_t*)K2, info->OPAD);
}
__host__ __device__ void _PBKDF2_HMAC_SHA256_salt_compute(uint8_t* salt, uint64_t saLen, uint32_t integer, PBKDF2_HMAC_SHA256_INFO* INFO, uint32_t* out)
{
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

__host__ __device__ void _PBKDF2_HMAC_SHA256_salt_compute_coalesced(uint8_t* salt, uint64_t saLen, uint32_t integer, PBKDF2_HMAC_SHA256_INFO* INFO, uint32_t* out, uint64_t p, uint64_t num_of_scrypt)
{
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
    _SHA256_process_coalesced(salt, saLen, &info, p, num_of_scrypt);
    _SHA256_process(temp, 4, &info);
    _SHA256_salt_compute_final(&info, out);
}

__host__ __device__ void _PBKDF2_HMAC_SHA256_core(uint32_t* _prestate, uint32_t* digest, uint32_t* in)
{

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
//기존 PBKDF2
__host__ __device__ void PBKDF2_HMAC_SHA256(uint8_t* pt, size_t ptLen, uint8_t* salt, size_t saLen, uint8_t* dkout, size_t dkLen, size_t iter)
{
    uint8_t buf[GPU_SHA256_BLOCK];
    uint32_t _first[8];
    uint32_t _second[8];
    PBKDF2_HMAC_SHA256_INFO info;
    uint32_t _TkLen = dkLen / GPU_SHA256_DIGEST;
    if (dkLen % GPU_SHA256_DIGEST != 0) { _TkLen++; }


    if (ptLen > GPU_SHA256_BLOCK)
    {
        _SHA256(pt, ptLen, buf);
        _PBKDF2_HMAC_SHA256_precompute(buf, GPU_SHA256_DIGEST, &info);
        info.ptLen = GPU_SHA256_DIGEST;
    }
    else
    {
        _PBKDF2_HMAC_SHA256_precompute(pt, ptLen, &info);
        info.ptLen = ptLen;
    }
    for (uint32_t i = 0; i < _TkLen; i++)
    {
        _PBKDF2_HMAC_SHA256_salt_compute(salt, saLen, i + 1, &info, _first);
        _PBKDF2_HMAC_SHA256_core(info.OPAD, _second, _first);
        for (int z = 0; z < 8; z++)
        {
            dkout[4 * z + 0] = (_second[z] >> 24) & 0xff;
            dkout[4 * z + 1] = (_second[z] >> 16) & 0xff;
            dkout[4 * z + 2] = (_second[z] >> 8) & 0xff;
            dkout[4 * z + 3] = (_second[z] >> 0) & 0xff;
        }
        dkout += 32;
    }
}
//출력값이 coalesced 정렬 패턴에 맞게 되는 PBKDF2
__host__ __device__ void PBKDF2_HMAC_SHA256_coalesced(uint8_t* pt, size_t ptLen, uint8_t* salt, size_t saLen, uint8_t* dkout, size_t dkLen, size_t iter, uint64_t p, uint64_t num_of_scrypt)
{
    uint8_t buf[GPU_SHA256_BLOCK];
    uint32_t _first[8];
    uint32_t _second[8];
    PBKDF2_HMAC_SHA256_INFO info;
    uint8_t* us_dkOUT;
    uint32_t _TkLen = dkLen / GPU_SHA256_DIGEST;
    uint32_t index0, i, j, us_TKLen, us_dkLen;
    us_TKLen = (_TkLen / p);
    us_dkLen = (dkLen / p);
    if (dkLen % GPU_SHA256_DIGEST != 0) { _TkLen++; }

    if (ptLen > GPU_SHA256_BLOCK)
    {
        _SHA256(pt, ptLen, buf);
        _PBKDF2_HMAC_SHA256_precompute(buf, GPU_SHA256_DIGEST, &info);
        info.ptLen = GPU_SHA256_DIGEST;
    }
    else
    {
        _PBKDF2_HMAC_SHA256_precompute(pt, ptLen, &info);
        info.ptLen = ptLen;
    }
    us_dkOUT = dkout;
    for (i = 0; i < p; i++) // p
    {
        us_dkOUT = dkout + i;
        for (j = 0; j < us_TKLen; j++)   // 4 * r
        {
            index0 = us_TKLen * i + j;
            _PBKDF2_HMAC_SHA256_salt_compute(salt, saLen, index0 + 1, &info, _first);
            _PBKDF2_HMAC_SHA256_core(info.OPAD, _second, _first);
            for (int z = 0; z < 8; z++)
            {
                *us_dkOUT = (_second[z] >> 24) & 0xff;
                us_dkOUT += num_of_scrypt * p;
                *us_dkOUT = (_second[z] >> 16) & 0xff;
                us_dkOUT += num_of_scrypt * p;
                *us_dkOUT = (_second[z] >> 8) & 0xff;
                us_dkOUT += num_of_scrypt * p;
                *us_dkOUT = (_second[z] >> 0) & 0xff;
                us_dkOUT += num_of_scrypt * p;
            }
        }
    }
}
//입력값, 출력값 모두 coalesced memory access에 사용되도록 정렬한 PBKDF2
__host__ __device__ void PBKDF2_HMAC_SHA256_coalesced2(uint8_t* pt, size_t ptLen, uint8_t* salt, size_t saLen, uint8_t* dkout, size_t dkLen, size_t iter, uint64_t p, uint64_t num_of_scrypt)
{
    uint8_t buf[GPU_SHA256_BLOCK];
    uint32_t _first[8];
    uint32_t _second[8];
    PBKDF2_HMAC_SHA256_INFO info;
    uint32_t _TkLen = dkLen / GPU_SHA256_DIGEST;
    if (dkLen % GPU_SHA256_DIGEST != 0) { _TkLen++; }

    if (ptLen > GPU_SHA256_BLOCK)
    {
        _SHA256(pt, ptLen, buf);
        _PBKDF2_HMAC_SHA256_precompute(buf, GPU_SHA256_DIGEST, &info);
        info.ptLen = GPU_SHA256_DIGEST;
    }
    else
    {
        _PBKDF2_HMAC_SHA256_precompute(pt, ptLen, &info);
        info.ptLen = ptLen;
    }
    for (uint32_t i = 0; i < _TkLen; i++)
    {
        _PBKDF2_HMAC_SHA256_salt_compute_coalesced(salt, saLen, i + 1, &info, _first, p, num_of_scrypt);
        _PBKDF2_HMAC_SHA256_core(info.OPAD, _second, _first);
        for (int z = 0; z < 8; z++)
        {
            dkout[4 * z + 0] = (_second[z] >> 24) & 0xff;
            dkout[4 * z + 1] = (_second[z] >> 16) & 0xff;
            dkout[4 * z + 2] = (_second[z] >> 8) & 0xff;
            dkout[4 * z + 3] = (_second[z] >> 0) & 0xff;
        }
        dkout += 32;
    }
}

__host__ __device__ void mix_block_for_coalesced(unsigned char* B, uint64_t r, uint64_t p, uint64_t num_of_scrypt)
{
    uint8_t* us_block = (uint8_t*)malloc(128 * r * p * num_of_scrypt);

    int k = 0;
    for (int i = 0; i < 128 * r; i++)   // 128 * r 만큼
    {
        for (int j = 0; j < p * num_of_scrypt; j++)
        {
            us_block[k++] = B[128 * r * j + i];
        }
    }
    k = 0;

    for (int i = 0; i < 128 * r * num_of_scrypt * p; i++)
    {
        B[i] = us_block[i];
    }
}

__device__ void salsa208_word_specification(uint32_t inout[16])
{
    int i;
    uint32_t x[16];
    memcpy(x, inout, sizeof(uint32_t) * 16);
    for (i = 8; i > 0; i -= 2)
    {
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
__device__ void scryptBlockMix(uint32_t* B_, uint32_t* B, uint64_t r)
{
    uint64_t i, j;
    uint32_t X[16], * pB;

    memcpy(X, B + (r * 2 - 1) * 16, sizeof(uint32_t) * 16);
    pB = B;
    for (i = 0; i < r * 2; i++)
    {
        for (j = 0; j < 16; j++)
            X[j] ^= *pB++;
        salsa208_word_specification(X);
        memcpy(B_ + (i / 2 + (i & 1) * r) * 16, X, sizeof(X));
    }
}
__device__ void scryptROMix(unsigned char* B, uint64_t r, uint64_t N, uint64_t p, uint64_t num_of_scrypt, uint32_t* X, uint32_t* T, uint32_t* V)    //B에 대한 coalesced memory access 방식은 가능할듯
{
    unsigned char* pB;
    uint32_t* pV;
    uint64_t i, k;
    uint64_t cycle0 = 0;
    uint64_t cycle1 = 0;

    /* Convert from little endian input */
    for (pV = V, i = 0, pB = B; i < 32 * r; i++, pV++)
    {
        *pV = *pB;
        pB += num_of_scrypt * p;
        *pV |= *pB << 8;
        pB += num_of_scrypt * p;
        *pV |= *pB << 16;
        pB += num_of_scrypt * p;
        *pV |= (uint32_t)*pB << 24;
        pB += num_of_scrypt * p;
    }
    for (i = 1; i < N; i++, pV += 32 * r)
        scryptBlockMix(pV, pV - 32 * r, r);

    scryptBlockMix(X, V + (N - 1) * 32 * r, r);

    for (i = 0; i < N; i++)
    {
        uint32_t j;
        j = X[16 * (2 * r - 1)] % N;
        pV = V + 32 * r * j;
        for (k = 0; k < 32 * r; k++)
            T[k] = X[k] ^ *pV++;
        scryptBlockMix(X, T, r);
    }
    /* Convert output to little endian */
    for (i = 0, pB = B; i < 32 * r; i++)
    {
        uint32_t xtmp = X[i];
        *pB = xtmp & 0xff;
        pB += num_of_scrypt * p;
        *pB = (xtmp >> 8) & 0xff;
        pB += num_of_scrypt * p;
        *pB = (xtmp >> 16) & 0xff;
        pB += num_of_scrypt * p;
        *pB = (xtmp >> 24) & 0xff;
        pB += num_of_scrypt * p;
    }
}

//CPU -> CPU
__global__ void GPU_scrypt_first_method(uint8_t* B, uint64_t N, uint64_t r, uint64_t p)
{
    uint64_t Blen, j;
    uint64_t tid = blockDim.x * blockIdx.x + threadIdx.x;
    uint64_t num_of_scrypt = gridDim.x;

    Blen = 128 * r * p * gridDim.x;

    uint32_t X[32 * 8]; // 여기에서 8은 r임
    uint32_t T[32 * 8];
    uint32_t* V = NULL;
    V = (uint32_t*)(B + Blen);

    scryptROMix(B + tid, r, N, p, num_of_scrypt, X, T, V + 1024 * r * 32 * tid);
}

//CPU -> GPU
__global__ void GPU_scrypt_second_method(uint8_t* B, uint8_t* pass, size_t passlen, uint64_t N, uint64_t r, uint64_t p, uint8_t* key, size_t keylen)
{
    uint64_t Blen, j, All_Blen;
    uint64_t tid = blockDim.x * blockIdx.x + threadIdx.x;
    uint64_t us_tid = threadIdx.x;
    uint64_t num_of_scrypt = gridDim.x;

    All_Blen = 128 * r * p * gridDim.x;
    Blen = 128 * r * p;

    uint32_t X[32 * 8]; // 여기에서 8은 r임
    uint32_t T[32 * 8];
    uint32_t* V = NULL;
    V = (uint32_t*)(B + All_Blen);

    scryptROMix(B + tid * 128 * r, r, N, p, num_of_scrypt, X, T, V + 1024 * r * 32 * tid);

    __syncthreads();

    // 이후의 PBKDF2과정에서 scryptROMix 하나의 block에 대한 전체 값에 대해서 집어넣어주어야 하기 때문에 1번의 Thread가 1번의 PBKDF2과정을 하면 안됨

    if (us_tid == 0)
    {
        PBKDF2_HMAC_SHA256(pass + (passlen * blockIdx.x), passlen, B + blockIdx.x * Blen, Blen, key + (keylen * blockIdx.x), keylen, 1);
    }
}

//GPU -> CPU
__global__ void GPU_scrypt_third_method(uint8_t* B, uint8_t* pass, size_t passlen, uint8_t* salt, size_t saltlen, uint64_t N, uint64_t r, uint64_t p)
{
    uint64_t Blen, All_Blen, j;
    uint64_t tid = blockDim.x * blockIdx.x + threadIdx.x;
    uint64_t us_tid = threadIdx.x;
    uint64_t num_of_scrypt = gridDim.x;

    All_Blen = 128 * r * p * gridDim.x;      //전체 블록의 길이
    Blen = 128 * r * p;                     //1개의 블록의 길이

    uint32_t X[32 * 8];                     // 여기에서 8은 r임
    uint32_t T[32 * 8];
    uint32_t* V = NULL;
    V = (uint32_t*)(B + All_Blen);

    if (us_tid == 0)
        PBKDF2_HMAC_SHA256_coalesced(pass + (passlen * blockIdx.x), passlen, salt + (saltlen * blockIdx.x), saltlen, B + (blockIdx.x * p), Blen, 1, p, num_of_scrypt);

    scryptROMix(B + tid, r, N, p, num_of_scrypt, X, T, V + 1024 * r * 32 * tid);
}

//GPU -> GPU
__global__ void GPU_scrypt_fourth_method(uint8_t* B, uint8_t* pass, size_t passlen, uint8_t* salt, size_t saltlen, uint64_t N, uint64_t r, uint64_t p, uint8_t* key, size_t keylen)
{
    uint64_t Blen, All_Blen, j;
    uint64_t tid = blockDim.x * blockIdx.x + threadIdx.x;
    uint64_t us_tid = threadIdx.x;
    uint64_t num_of_scrypt = gridDim.x;

    All_Blen = 128 * r * p * gridDim.x;      //전체 블록의 길이
    Blen = 128 * r * p;                     //1개의 블록의 길이

    uint32_t X[32 * 8];                     // 여기에서 8은 r임
    uint32_t T[32 * 8];
    uint32_t* V = NULL;
    V = (uint32_t*)(B + All_Blen);

    if (us_tid == 0)
        PBKDF2_HMAC_SHA256_coalesced(pass + (passlen * blockIdx.x), passlen, \
            salt + (saltlen * blockIdx.x), saltlen, B + blockIdx.x * p, Blen, 1, p, num_of_scrypt);

    scryptROMix(B + tid, r, N, p, num_of_scrypt, X, T, V + 1024 * r * 32 * tid);
 
    // 이후의 PBKDF2과정에서 scryptROMix 하나의 block에 대한 전체 값에 대해서 집어넣어주어야 하기 때문에 1번의 Thread가 1번의 PBKDF2과정을 하면 안됨
    if (us_tid == 0)
        PBKDF2_HMAC_SHA256_coalesced2(pass + (passlen * blockIdx.x), passlen, \
            B + blockIdx.x * p, Blen, key + (keylen * blockIdx.x), keylen, 1, p, num_of_scrypt);
}

//GPU -> GPU (PBKDF2) -> blocksize: p, threadsize: scrypt
__global__ void GPU_scrypt_fifth_method(uint8_t* B, uint8_t* pass, size_t passlen, uint8_t* salt, size_t saltlen, uint64_t N, uint64_t r, uint64_t p, uint8_t* key, size_t keylen)
{
    uint64_t Blen, All_Blen, j;
    uint64_t us_tid = blockDim.x * blockIdx.x + threadIdx.x;
    uint64_t bid = blockIdx.x;
    uint64_t tid = threadIdx.x;
    uint64_t num_of_scrypt = gridDim.x * blockDim.x;

    All_Blen = 128 * r * p * gridDim.x * blockDim.x;                        //전체 블록의 길이
    Blen = 128 * r * p;                                                     //1개의 블록의 길이

    uint32_t X[32 * 8];                                                     // 여기에서 8은 r임
    uint32_t T[32 * 8];
    uint32_t* V = NULL;
    V = (uint32_t*)(B + All_Blen);

    PBKDF2_HMAC_SHA256_coalesced(pass + (passlen * blockIdx.x), passlen, \
        salt + (saltlen * blockIdx.x), saltlen, B + blockIdx.x * p, Blen, 1, p, num_of_scrypt);

    for (int x = 0; x < p; x++)
        scryptROMix(B + ((p * p * bid + tid + p * x)), \
            r, N, p, num_of_scrypt, X, T, V + (N * r * 32 * (p * p * bid + tid + p * x)));

    PBKDF2_HMAC_SHA256_coalesced2(pass + (passlen * us_tid), passlen, \
        B + us_tid * p, Blen, key + (keylen * us_tid), keylen, 1, p, num_of_scrypt);
}

// 아래의 코드는 여러개의 scrypt에서 p의 값이 1이상일 때 p에 대한 병렬 구현을 하기 위한 코드이다.
// 그러므로 blocksize 는 scrypt의 개수 threadsize 는 p의 개수를 나타낸다.

// 아래의 코드는 모든 PBKDF2를 CPU에서 하는 코드이다.
void performance_test_scrypt_1(uint32_t blocksize, uint32_t threadsize)
{
    cudaError_t err;
    cudaEvent_t start, stop;
    uint8_t password[8] = { 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64 };
    uint8_t salt[4] = { 0x4e, 0x61, 0x43, 0x6c };
    uint8_t* cpu_key = (uint8_t*)malloc(64 * blocksize);

    uint8_t* gpu_pass = NULL;
    uint8_t* gpu_salt = NULL;
    uint8_t* gpu_key = NULL;
    uint8_t* gpu_b = NULL;
    uint64_t Blen = 128 * threadsize * 8;                               //128 * p * r
    uint64_t Vlen = 32 * 8 * 1024 * sizeof(uint32_t) * threadsize;      //내부에서 사용하는 Vector의 길이로 현재의 코드에서는 각 p마다 서로 다른 Vector의 메모리를 사용해야하기 때문에 blocksize * threadsize 를 해주어야 한다.
    uint64_t total = Blen + Vlen;
    float elapsed_time_ms = 0.0f;

    uint8_t* cpu_block = (uint8_t*)malloc(Blen * blocksize);

    uint8_t* us_cpu_block = (uint8_t*)malloc(Blen * blocksize);         //coalesed memory access

    uint8_t* cpu_pass = (uint8_t*)malloc(8 * blocksize);

    //cudaMalloc((void**)&gpu_pass, 8);
    //cudaMalloc((void**)&gpu_salt, 4);
    //cudaMalloc((void**)&gpu_key, 64);   // PBKDF2를 GPU에서 하지 않기 때문에 사용하지 않아도 됨

    err = cudaMalloc((void**)&gpu_b, total * blocksize);
    if (err != cudaSuccess)
    {
        printf("gpu_b : CUDA error : %s\n", cudaGetErrorString(err));
    }

    cudaEventCreate(&start);
    cudaEventCreate(&stop);
    cudaEventRecord(start, 0);

    for (int i = 0; i < blocksize; i++)
    {
        //PBKDF2_HMAC_SHA256(password, 8, salt, 4, cpu_block + i * Blen, Blen, 1);
        PBKDF2_HMAC_SHA256_coalesced(password, 8, salt, 4, cpu_block + i * threadsize, Blen, 1, threadsize, blocksize);

        memcpy(cpu_pass + (i * 8), password, sizeof(uint8_t) * 8);            //pass가 동일해야하므로 이렇게

        password[7] = (i + 1) & 0xff;                                 //한 번 반복 때마다 password를 변환시켜주기 위함 -> 변환하고자 하는 코드에서는 안해줘도 됨
        salt[3] = (i + 2) & 0xff;
    }

    //mix_block_for_coalesced(cpu_block, 8, threadsize, blocksize);
    //int k = 0;
    //for (int i = 0; i < 128 * 8; i++)   // 128 * r 만큼
    //{
    //    for (int j = 0; j < threadsize * blocksize; j++)
    //    {
    //        us_cpu_block[k++] = cpu_block[128 * 8 * j + i];
    //    }
    //}
    //k = 0;

    cudaMemcpy(gpu_b, cpu_block, Blen * blocksize, cudaMemcpyHostToDevice);   //gpu_b에 cpu_block 즉 PBKDF2의 결과값을 복사해줌 (blocksize만큼의 scrypt알고리즘을 사용해야 하기 때문에 이렇게 해야함)

    GPU_scrypt_first_method << <blocksize, threadsize >> > (gpu_b, 1024, 8, threadsize);

    cudaMemcpy(us_cpu_block, gpu_b, Blen * blocksize, cudaMemcpyDeviceToHost);

    int k = 0;
    for (int i = 0; i < blocksize * threadsize; i++)        // num_of_scrypt * p
    {
        for (int j = 0; j < 128 * 8; j++)                   // 128 * r
        {
            cpu_block[k++] = us_cpu_block[blocksize * threadsize * j + i];
        }
    }
    k = 0;

    for (int i = 0; i < blocksize; i++)
    {
        PBKDF2_HMAC_SHA256(cpu_pass + (8 * i), 8, cpu_block + (Blen * i), Blen, cpu_key + (64 * i), 64, 1);
    }

    cudaEventRecord(stop, 0);
    cudaDeviceSynchronize();
    cudaEventSynchronize(start);
    cudaEventSynchronize(stop);
    cudaEventElapsedTime(&elapsed_time_ms, start, stop);
    printf("%4.2f\n", elapsed_time_ms);

    for (int i = 0; i < 64 * blocksize; i++)
    {
        printf("%02X ", cpu_key[i]);
        if ((i + 1) % 16 == 0)
            printf("\n");
        if ((i + 1) % 64 == 0)
            printf("\n");
    }

    printf("first method's <<<%d, %d>>> scrypt per second is : %4.2f\n", blocksize, threadsize, (1000 / elapsed_time_ms) * blocksize);

    cudaFree(gpu_pass);
    cudaFree(gpu_salt);
    cudaFree(gpu_b);
    cudaFree(gpu_key);
    free(cpu_key);
    free(cpu_block);
    free(us_cpu_block);
    free(cpu_pass);
}

// 아래의 코드는 첫번째 PBKDF2를 CPU, 두번째 PBKDF2를 GPU에서 하는 코드이다.
void performance_test_scrypt_2(uint32_t blocksize, uint32_t threadsize)
{
    cudaError_t err;
    cudaEvent_t start, stop;
    uint8_t password[8] = { 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64 };
    uint8_t salt[4] = { 0x4e, 0x61, 0x43, 0x6c };
    uint8_t* cpu_key = (uint8_t*)malloc(64 * blocksize);

    uint8_t* gpu_pass = NULL;
    uint8_t* gpu_key = NULL;
    uint8_t* gpu_b = NULL;
    uint64_t Blen = 128 * threadsize * 8;                                                //128 * p * r
    uint64_t Vlen = 32 * 8 * 1024 * sizeof(uint32_t) * threadsize;                        //내부에서 사용하는 Vector의 길이로 현재의 코드에서는 각 p마다 서로 다른 Vector의 메모리를 사용해야하기 때문에 blocksize * threadsize 를 해주어야 한다.
    uint64_t total = Blen + Vlen;
    float elapsed_time_ms = 0.0f;

    uint8_t* cpu_block = (uint8_t*)malloc(Blen * blocksize);

    cudaMalloc((void**)&gpu_pass, 8 * blocksize);
    cudaMalloc((void**)&gpu_key, 64 * blocksize);

    err = cudaMalloc((void**)&gpu_b, total * blocksize);
    if (err != cudaSuccess)
    {
        printf("gpu_b : CUDA error : %s\n", cudaGetErrorString(err));
    }

    cudaEventCreate(&start);
    cudaEventCreate(&stop);
    cudaEventRecord(start, 0);

    for (int i = 0; i < blocksize; i++)
    {
        PBKDF2_HMAC_SHA256(password, 8, salt, 4, cpu_block + (Blen * i), Blen, 1);

        cudaMemcpy(gpu_pass + (8 * i), password, 8, cudaMemcpyHostToDevice);

        password[7] = (i + 1) & 0xff;
        salt[3] = (i + 2) & 0xff;
    }

    cudaMemcpy(gpu_b, cpu_block, Blen * blocksize, cudaMemcpyHostToDevice);                                                            //gpu_b에 cpu_block 즉 PBKDF2의 결과값을 복사해줌 (blocksize만큼의 scrypt알고리즘을 사용해야 하기 때문에 이렇게 해야함)

    GPU_scrypt_second_method << <blocksize, threadsize >> > (gpu_b, gpu_pass, 8, 1024, 8, threadsize, gpu_key, 64);

    cudaMemcpy(cpu_key, gpu_key, 64 * blocksize, cudaMemcpyDeviceToHost);

    cudaEventRecord(stop, 0);
    cudaDeviceSynchronize();
    cudaEventSynchronize(start);
    cudaEventSynchronize(stop);
    cudaEventElapsedTime(&elapsed_time_ms, start, stop);
    printf("%4.2f\n", elapsed_time_ms);

    /*for (int i = 0; i < 64 * blocksize; i++)
    {
        printf("%02X ", cpu_key[i]);
        if ((i + 1) % 16 == 0)
            printf("\n");
        if ((i + 1) % 64 == 0)
            printf("\n");
    }*/

    printf("second method's <<<%d, %d>>> scrypt per second is : %4.2f\n", blocksize, threadsize, 1000 / elapsed_time_ms * blocksize);

    cudaFree(gpu_pass);
    cudaFree(gpu_b);
    cudaFree(gpu_key);
    free(cpu_key);
    free(cpu_block);
}

// 아래의 코드는 첫번쨰 PBKDF2를 GPU, 두번째 PBKDF2를 CPU에서 하는 코드이다.
void performance_test_scrypt_3(uint32_t blocksize, uint32_t threadsize)
{
    cudaError_t err;
    cudaEvent_t start, stop;
    uint8_t password[8] = { 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64 };
    uint8_t salt[4] = { 0x4e, 0x61, 0x43, 0x6c };
    uint8_t* cpu_key = (uint8_t*)malloc(64 * blocksize);
    if (cpu_key == NULL)
    {
        return;
    }

    uint8_t* gpu_pass = NULL;
    uint8_t* gpu_salt = NULL;
    uint8_t* gpu_key = NULL;
    uint8_t* gpu_b = NULL;
    uint64_t Blen = 128 * threadsize * 8;                                             //128 * p * r
    uint64_t Vlen = 32 * 8 * 1024 * sizeof(uint32_t) * threadsize;                     //내부에서 사용하는 Vector의 길이로 현재의 코드에서는 각 p마다 서로 다른 Vector의 메모리를 사용해야하기 때문에 blocksize * threadsize 를 해주어야 한다.
    uint64_t total = Blen + Vlen;
    float elapsed_time_ms = 0.0f;

    uint8_t* cpu_block = (uint8_t*)malloc(Blen * blocksize);

    uint8_t* us_cpu_block = (uint8_t*)malloc(Blen * blocksize);         //coalesed memory access

    uint8_t* cpu_pass = (uint8_t*)malloc(8 * blocksize);

    cudaMalloc((void**)&gpu_pass, 8 * blocksize);
    cudaMalloc((void**)&gpu_salt, 4 * blocksize);

    err = cudaMalloc((void**)&gpu_b, total * blocksize);
    if (err != cudaSuccess)
    {
        printf("gpu_b : CUDA error : %s\n", cudaGetErrorString(err));
    }

    cudaEventCreate(&start);
    cudaEventCreate(&stop);
    cudaEventRecord(start, 0);

    for (int i = 0; i < blocksize; i++)
    {
        cudaMemcpy(gpu_pass + (8 * i), password, 8, cudaMemcpyHostToDevice);
        cudaMemcpy(gpu_salt + (4 * i), salt, 4, cudaMemcpyHostToDevice);

        memcpy(cpu_pass + (i * 8), password, sizeof(uint8_t) * 8);

        password[7] = (i + 1) & 0xff;                                                //한 번 반복 때마다 password를 변환시켜주기 위함 -> 변환하고자 하는 코드에서는 안해줘도 됨
        salt[3] = (i + 2) & 0xff;
    }

    GPU_scrypt_third_method << <blocksize, threadsize >> > (gpu_b, gpu_pass, 8, gpu_salt, 4, 1024, 8, threadsize);

    cudaMemcpy(cpu_block, gpu_b, Blen * blocksize, cudaMemcpyDeviceToHost);

    int k = 0;
    for (int i = 0; i < blocksize * threadsize; i++)
    {
        for (int j = 0; j < 128 * 8; j++)
        {
            us_cpu_block[k++] = cpu_block[blocksize * threadsize * j + i];
        }
    }
    k = 0;

    for (int i = 0; i < blocksize; i++)
    {
        PBKDF2_HMAC_SHA256(cpu_pass + (8 * i), 8, us_cpu_block + (Blen * i), Blen, cpu_key + (64 * i), 64, 1);
    }

    cudaEventRecord(stop, 0);
    cudaDeviceSynchronize();
    cudaEventSynchronize(start);
    cudaEventSynchronize(stop);
    cudaEventElapsedTime(&elapsed_time_ms, start, stop);
    printf("%4.2f\n", elapsed_time_ms);

    //for (int i = 0; i < 64 * blocksize; i++)
    //{
    //    printf("%02X ", cpu_key[i]);
    //    if ((i + 1) % 16 == 0)
    //        printf("\n");
    //    if ((i + 1) % 64 == 0)
    //        printf("\n");
    //}

    printf("third method's <<<%d, %d>>> scrypt per second is : %4.2f\n", blocksize, threadsize, 1000 / elapsed_time_ms * blocksize);

    cudaFree(gpu_pass);
    cudaFree(gpu_salt);
    cudaFree(gpu_b);
    cudaFree(gpu_key);
    free(cpu_key);
    free(cpu_block);
}

//아래의 코드는 모든 PBKDF2를 GPU에서 하는 코드이다.
void performance_test_scrypt_4(uint32_t blocksize, uint32_t threadsize)
{
    cudaError_t err;
    cudaEvent_t start, stop;
    uint8_t password[8] = { 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64 };
    uint8_t salt[4] = { 0x4e, 0x61, 0x43, 0x6c };
    uint8_t* cpu_key = (uint8_t*)malloc(64 * blocksize);
    if (cpu_key == NULL)
    {
        return;
    }

    uint8_t* gpu_pass = NULL;
    uint8_t* gpu_salt = NULL;
    uint8_t* gpu_key = NULL;
    uint8_t* gpu_b = NULL;
    uint64_t Blen = 128 * threadsize * 8;                                 //128 * p * r
    uint64_t Vlen = 32 * 8 * 1024 * sizeof(uint32_t) * threadsize;      //내부에서 사용하는 Vector의 길이로 현재의 코드에서는 각 p마다 서로 다른 Vector의 메모리를 사용해야하기 때문에 blocksize * threadsize 를 해주어야 한다.
    uint64_t total = Blen + Vlen;
    float elapsed_time_ms = 0.0f;

    cudaMalloc((void**)&gpu_pass, 8 * blocksize);
    cudaMalloc((void**)&gpu_salt, 4 * blocksize);
    cudaMalloc((void**)&gpu_key, 64 * blocksize);

    err = cudaMalloc((void**)&gpu_b, total * blocksize);
    if (err != cudaSuccess)
    {
        printf("gpu_b : CUDA error : %s\n", cudaGetErrorString(err));
    }

    cudaEventCreate(&start);
    cudaEventCreate(&stop);
    cudaEventRecord(start, 0);

    for (int i = 0; i < blocksize; i++)
    {
        cudaMemcpy(gpu_pass + (8 * i), password, 8, cudaMemcpyHostToDevice);
        cudaMemcpy(gpu_salt + (4 * i), salt, 4, cudaMemcpyHostToDevice);
        password[7] = (i + 1) & 0xff;                                 //한 번 반복 때마다 password를 변환시켜주기 위함 -> 변환하고자 하는 코드에서는 안해줘도 됨
        salt[3] = (i + 2) & 0xff;
    }

    GPU_scrypt_fourth_method << <blocksize, threadsize >> > (gpu_b, gpu_pass, 8, gpu_salt, 4, 1024, 8, threadsize, gpu_key, 64);

    cudaMemcpy(cpu_key, gpu_key, 64 * blocksize, cudaMemcpyDeviceToHost);

    cudaEventRecord(stop, 0);
    cudaDeviceSynchronize();
    cudaEventSynchronize(start);
    cudaEventSynchronize(stop);
    cudaEventElapsedTime(&elapsed_time_ms, start, stop);
    printf("%4.2f\n", elapsed_time_ms);

    for (int i = 0; i < 64 * blocksize; i++)
    {
       printf("%02X ", cpu_key[i]);
       if ((i + 1) % 16 == 0)
          printf("\n");
       if ((i + 1) % 64 == 0)
          printf("\n");
    }

    printf("fourth method's <<<%d, %d>>> scrypt per second is : %4.2f\n", blocksize, threadsize, 1000 / elapsed_time_ms * blocksize);

    cudaFree(gpu_pass);
    cudaFree(gpu_salt);
    cudaFree(gpu_b);
    cudaFree(gpu_key);
    free(cpu_key);
}

//아래의 코드는 PBKDF2까지 GPU상에서 병렬화 하는 코드이다.
//실제로 global함수에 들어갈 때의 parameter는 <<<blocksize / threadsize, threadsize>>> 이며
//여기에서 block의 크기는 한번에 연산하는 scrypt의 개수 / p를 나타내며, thread는 p를 나타낸다
void performance_test_scrypt_5(uint32_t num_of_scrypt, uint32_t threadsize)
{
    cudaError_t err;
    cudaEvent_t start, stop;
    uint8_t password[GPU_PASSWORD_LEN] = { 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64 };
    uint8_t salt[4] = { 0x4e, 0x61, 0x43, 0x6c };
    uint8_t* cpu_key = (uint8_t*)malloc(64 * num_of_scrypt);

    if (cpu_key == NULL)
    {
        return;
    }

    uint8_t* gpu_pass = NULL;
    uint8_t* gpu_salt = NULL;
    uint8_t* gpu_key = NULL;
    uint8_t* gpu_b = NULL;
    uint64_t Blen = 128 * threadsize * 8;                                       //128 * p * r
    uint64_t Vlen = 32 * 8 * 1024 * sizeof(uint32_t) * threadsize;              //내부에서 사용하는 Vector의 길이로 현재의 코드에서는 각 p마다 서로 다른 Vector의 메모리를 사용해야하기 때문에 blocksize * threadsize 를 해주어야 한다.
    uint64_t total = Blen + Vlen;
    float elapsed_time_ms = 0.0f;

    cudaMalloc((void**)&gpu_pass, GPU_PASSWORD_LEN * num_of_scrypt);
    cudaMalloc((void**)&gpu_salt, 4 * num_of_scrypt);
    cudaMalloc((void**)&gpu_key, 64 * num_of_scrypt);

    err = cudaMalloc((void**)&gpu_b, total * num_of_scrypt);
    if (err != cudaSuccess)
    {
        printf("gpu_b : CUDA error : %s\n", cudaGetErrorString(err));
    }

    cudaEventCreate(&start);
    cudaEventCreate(&stop);
    cudaEventRecord(start, 0);

    for (int i = 0; i < num_of_scrypt; i++)
    {
        cudaMemcpy(gpu_pass + (GPU_PASSWORD_LEN * i), password, 8, cudaMemcpyHostToDevice);
        cudaMemcpy(gpu_salt + (4 * i), salt, 4, cudaMemcpyHostToDevice);

        password[7] = (i + 1) & 0xff;                                               //한 번 반복 때마다 password를 변환시켜주기 위함 -> 변환하고자 하는 코드에서는 안해줘도 됨
        salt[3] = (i + 2) & 0xff;
    }

    GPU_scrypt_fifth_method << < num_of_scrypt / threadsize, threadsize >> > (gpu_b, gpu_pass, GPU_PASSWORD_LEN, gpu_salt, 4, 1024, 8, threadsize, gpu_key, 64);

    cudaMemcpy(cpu_key, gpu_key, 64 * num_of_scrypt, cudaMemcpyDeviceToHost);

    cudaEventRecord(stop, 0);
    cudaDeviceSynchronize();
    cudaEventSynchronize(start);
    cudaEventSynchronize(stop);
    cudaEventElapsedTime(&elapsed_time_ms, start, stop);
    printf("%4.2f\n", elapsed_time_ms);

    for (int i = 0; i < 64 * num_of_scrypt; i++)
    {
        printf("%02X ", cpu_key[i]);
        if ((i + 1) % 16 == 0)
            printf("\n");
        if ((i + 1) % 64 == 0)
            printf("\n");
    }

    printf("fifth method's <<<%d, %d>>> scrypt per second is : %4.2f\n", num_of_scrypt / threadsize, threadsize, 1000 / elapsed_time_ms * num_of_scrypt);

    cudaFree(gpu_pass);
    cudaFree(gpu_salt);
    cudaFree(gpu_b);
    cudaFree(gpu_key);
    free(cpu_key);
}

int main()
{
    performance_test_scrypt_4(32, 2);
    //performance_test_scrypt_1(64, 2);
    //performance_test_scrypt_1(128, 2);
    //performance_test_scrypt_1(256, 2);
    //performance_test_scrypt_1(512, 2);
    //performance_test_scrypt_1(1024, 2);
    //performance_test_scrypt_1(2048, 2);

    //performance_test_scrypt_2(32, 4);
    //performance_test_scrypt_2(64, 4);
    //performance_test_scrypt_2(128, 4);
    //performance_test_scrypt_2(256, 4);
    //performance_test_scrypt_2(512, 4);
    //performance_test_scrypt_2(1024, 4);
    //performance_test_scrypt_2(2048, 4);

    //performance_test_scrypt_3(32, 2);
    //performance_test_scrypt_3(64, 2);
    //performance_test_scrypt_3(128, 2);
    //performance_test_scrypt_3(256, 2);
    //performance_test_scrypt_3(512, 2); 
    //performance_test_scrypt_3(1024, 2);
    //performance_test_scrypt_3(2048, 2);

    //performance_test_scrypt_4(32, 4);
    //performance_test_scrypt_4(64, 4);
    //performance_test_scrypt_4(128, 4);
    //performance_test_scrypt_4(256, 4);
    //performance_test_scrypt_4(512, 4);
    //performance_test_scrypt_4(1024, 4);
    //performance_test_scrypt_4(2048, 4);

    //performance_test_scrypt_5(32, 4);   // 기존과 같은 방식나타내는게 보기 쉬울것 같아서 이렇게 나타냄      
    //performance_test_scrypt_5(64, 4);  
    //performance_test_scrypt_5(128, 4);
    //performance_test_scrypt_5(256, 4);
    //performance_test_scrypt_5(512, 4);
    //performance_test_scrypt_5(1024, 4);
    //performance_test_scrypt_5(2048, 4);

}