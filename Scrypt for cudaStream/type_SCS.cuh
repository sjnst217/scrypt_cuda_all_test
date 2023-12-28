#include "cuda_runtime.h"
#include "device_launch_parameters.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define Scrypt_R(a,b)	(((a) << (b)) | ((a) >> (32-(b))))
#define Scrypt_GPU_SHIFT_RIGHT_32(x,n) ((x) >> (n))
#define Scrypt_GPU_rotl32(x, n)		(((x) << (n)) | ((x) >> (32 - (n))))
#define Scrypt_GPU_rotr32(x, n)		(((x) >> (n)) | ((x) << (32 - (n))))
#define Scrypt_GPU_ENDIAN_CHANGE32(X)		((Scrypt_GPU_rotl32((X),  8) & 0x00ff00ff) | (Scrypt_GPU_rotl32((X), 24) & 0xff00ff00))

#define Scrypt_GPU_SHA256_DIGEST		32
#define Scrypt_GPU_SHA256_BLOCK		64
#define Scrypt_GPU_add3(a, b, c)		(a + b + c)
#define Scrypt_GPU_SHA256_F0(x,y,z)	(((x) & (y)) | ((z) & ((x) ^ (y))))
#define Scrypt_GPU_SHA256_F1(x,y,z)	((z) ^ ((x) & ((y) ^ (z))))
#define Scrypt_GPU_SHA256_F0o(x,y,z) (Scrypt_GPU_SHA256_F0 ((x), (y), (z)))
#define Scrypt_GPU_SHA256_F1o(x,y,z) (Scrypt_GPU_SHA256_F1 ((x), (y), (z)))
#define Scrypt_GPU_SHA256_S0(x) (Scrypt_GPU_rotl32 ((x), 25u) ^ Scrypt_GPU_rotl32 ((x), 14u) ^ Scrypt_GPU_SHIFT_RIGHT_32 ((x),  3u))
#define Scrypt_GPU_SHA256_S1(x) (Scrypt_GPU_rotl32 ((x), 15u) ^ Scrypt_GPU_rotl32 ((x), 13u) ^ Scrypt_GPU_SHIFT_RIGHT_32 ((x), 10u))
#define Scrypt_GPU_SHA256_S2(x) (Scrypt_GPU_rotl32 ((x), 30u) ^ Scrypt_GPU_rotl32 ((x), 19u) ^ Scrypt_GPU_rotl32 ((x), 10u))
#define Scrypt_GPU_SHA256_S3(x) (Scrypt_GPU_rotl32 ((x), 26u) ^ Scrypt_GPU_rotl32 ((x), 21u) ^ Scrypt_GPU_rotl32 ((x),  7u))
#define Scrypt_GPU_SHA256_EXPAND(x,y,z,w) (Scrypt_GPU_SHA256_S1 (x) + y + Scrypt_GPU_SHA256_S0 (z) + w)
#define Scrypt_GPU_SHA256_STEP(F0,F1,a,b,c,d,e,f,g,h,x,K)    \
{                                                 \
  h = Scrypt_GPU_add3 (h, K, x);                          \
  h = Scrypt_GPU_add3 (h, Scrypt_GPU_SHA256_S3 (e), F1 (e,f,g));     \
  d += h;                                         \
  h = Scrypt_GPU_add3 (h, Scrypt_GPU_SHA256_S2 (a), F0 (a,b,c));     \
}
