#include "cuda_runtime.h"
#include "device_launch_parameters.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define R(a,b)	(((a) << (b)) | ((a) >> (32-(b))))
#define GPU_SHIFT_RIGHT_32(x,n) ((x) >> (n))
#define GPU_rotl32(x, n)		(((x) << (n)) | ((x) >> (32 - (n))))
#define GPU_rotr32(x, n)		(((x) >> (n)) | ((x) << (32 - (n))))
#define GPU_ENDIAN_CHANGE32(X)		((GPU_rotl32((X),  8) & 0x00ff00ff) | (GPU_rotl32((X), 24) & 0xff00ff00))

#define GPU_SHA256_DIGEST		32
#define GPU_SHA256_BLOCK		64
#define GPU_add3(a, b, c)		(a + b + c)
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
