// CC0 - http://creativecommons.org/publicdomain/zero/1.0/
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_MSC_VER)
#include <intrin.h>
#pragma intrinsic(__rdtsc)

#include <winsock2.h>
#define htobe16(x) htons(x)
#define be16toh(x) ntohs(x)
#define htobe32(x) htonl(x)
#define be32toh(x) ntohl(x)
#define htobe64(x) htonll(x)
#define be64toh(x) ntohll(x)
#else
#include <endian.h>
#endif // _MSC_VER

size_t size = 1000000;
size_t iterations = 1000;

uint8_t *data;
size_t item_count = 0;

uint8_t cid_len(uint8_t r) { return 1 + (r + 5) * (!!r); }

// Allocate some memory for the data.
bool setup() {
  data = malloc(size);
  if (!data) {
    return false;
  }

  FILE *urandom = fopen("/dev/urandom", "r");
  if (!urandom) {
    return false;
  }

  size_t done = 0;
  while (done < size) {
    size_t read_count = fread(data + done, sizeof(*data), size - done, urandom);
    if (!read_count) {
      fclose(urandom);
      return false;
    }
    done += read_count;
  }
  fclose(urandom);

  // Now take a few bytes and rework them to produce sensible values.
  //   struct {
  //     uint8 header_len;
  //     uint8 token_len;
  //     uint8 odcid_len; -- last so that it can be used directly
  //   };
  size_t i = 0;
  while (i + 3 < size) {
    uint8_t header_len = 5 + cid_len(data[i] & 0xf) + cid_len(data[i] >> 4);
    data[i++] = header_len;
    uint8_t token_len = 32 + (data[i] & 0xf);
    data[i++] = token_len;
    uint8_t odcid_len = 8 + (((data[i] >> 2) | data[i]) & 3);
    data[i++] = odcid_len;
    i += odcid_len + header_len + token_len;
    if (i < size) {
      item_count++;
    }
  }

  return true;
}

void cleanup() { free(data); }

// Tweaked timing function from the Keccak reference implementation
static uint32_t hires_time() {
  uint32_t x[2];
#ifdef _MSC_VER
  x[0] = (uint32_t)__rdtsc();
#else
  __asm__ volatile("rdtsc" : "=a"(x[0]), "=d"(x[1]));
#endif
  return x[0];
}

uint32_t benchmark_floor = 0;
#define MEASURE(_name)                                                         \
  void _run_##_name();                                                         \
  uint32_t measure_##_name() {                                                 \
    uint32_t tmin = UINT32_MAX;                                                \
    for (size_t i = 0; i < iterations; ++i) {                                  \
      uint32_t t0 = hires_time();                                              \
      _run_##_name();                                                          \
      uint32_t t1 = hires_time();                                              \
      if (tmin > t1 - t0 - benchmark_floor) {                                  \
        tmin = t1 - t0 - benchmark_floor;                                      \
      }                                                                        \
    }                                                                          \
    return tmin;                                                               \
  }                                                                            \
  inline void _run_##_name()

MEASURE(calibrate) {}

#include "blapi.h"
#include "blapit.h"
#define NSS_X86_OR_X64 1
#include "ctr.h"
#include "gcm.h"
#include "pkcs11t.h"
#include "rijndael.h"
#include <assert.h>
#define SUCCESS(_e)                                                            \
  do {                                                                         \
    SECStatus rv = (_e);                                                       \
    if (rv != SECSuccess) {                                                    \
      fprintf(stderr, "Error in: %s\n", #_e);                                  \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)

static const uint8_t retry_key[16] = {0xf5, 0xed, 0x46, 0x42, 0xe0, 0xe4,
                                      0xc8, 0xd8, 0x78, 0xbb, 0xbc, 0x8a,
                                      0x82, 0x88, 0x21, 0xc9};
static const uint8_t gcm_H[16] = {0xe6, 0xad, 0x60, 0x0d, 0xdb, 0xbc,
                                  0xb2, 0x68, 0xc3, 0x32, 0x00, 0x49,
                                  0x99, 0x69, 0xa9, 0xad};
static const uint8_t tag_mask[16] = {

    0xea, 0x19, 0x0a, 0x5d, 0x49, 0xbb, 0x5f, 0x80,
    0x9d, 0xc8, 0x12, 0x2f, 0x80, 0xb0, 0xe3, 0x25};

MEASURE(ghash) {
  uint8_t scratch[128];

  gcmHashContext cx;
  SUCCESS(gcmHash_InitContext(&cx, gcm_H, false));
  const uint8_t *cursor = data;
  for (size_t i = 0; i < item_count; ++i) {
    // Lump the header and token together for this method.
    size_t header_len = *cursor++;
    header_len += *cursor++;

    const uint8_t *gcm_start = cursor;
    size_t odcid_len = *cursor++;
    cursor += odcid_len;

    const uint8_t *header = cursor;
    cursor += header_len;

    assert(header_len + 16 <= sizeof(scratch));
    memcpy(scratch, header, header_len);

    SUCCESS(gcmHash_Reset(&cx, gcm_start, 1 + odcid_len + header_len));
    unsigned int out_len = 0;
    SUCCESS(gcmHash_Final(&cx, scratch + header_len, &out_len, 16));

    for (size_t j = 0; j < 16; ++j) {
      scratch[header_len + j] ^= tag_mask[j];
    }
  }
}

#ifdef NEED_PARAMETERS
void get_parameters() {
  AESContext cx;
  static uint8_t iv[12] = {0};
  CK_GCM_PARAMS gcm_params = {
      .pIv = (CK_BYTE_PTR)iv,
      .ulIvLen = sizeof(iv),
      .pAAD = NULL,
      .ulAADLen = 0,
      .ulTagBits = 128,
  };
  static const uint8_t retry_key[16] = {0xf5, 0xed, 0x46, 0x42, 0xe0, 0xe4,
                                        0xc8, 0xd8, 0x78, 0xbb, 0xbc, 0x8a,
                                        0x82, 0x88, 0x21, 0xc9};
  SUCCESS(AES_InitContext(&cx, retry_key, sizeof(retry_key),
                          (const uint8_t *)&gcm_params, NSS_AES_GCM, 1,
                          AES_BLOCK_SIZE));
}
#endif

MEASURE(aes_gcm_slow) {
  uint8_t scratch[128];

  AESContext cx;
  static uint8_t iv[12] = {0};
  CK_GCM_PARAMS gcm_params = {
      .pIv = (CK_BYTE_PTR)iv,
      .ulIvLen = sizeof(iv),
      .pAAD = NULL,
      .ulAADLen = 0,
      .ulTagBits = 128,
  };

  const uint8_t *cursor = data;
  for (size_t i = 0; i < item_count; ++i) {
    // Read both the header and token lengths as this method doesn't
    // distinguish.
    size_t header_len = *cursor++;
    size_t token_len = *cursor++;

    size_t odcid_len = *cursor++;
    cursor += odcid_len;

    const uint8_t *header = cursor;
    memcpy(scratch, header, header_len);
    cursor += header_len;
    const uint8_t *token = cursor;
    cursor += token_len;

    gcm_params.pAAD = (uint8_t *)header; // stupid const-cast.
    gcm_params.ulAADLen = header_len;

    SUCCESS(AES_InitContext(&cx, retry_key, sizeof(retry_key),
                            (const uint8_t *)&gcm_params, NSS_AES_GCM, 1,
                            AES_BLOCK_SIZE));
    unsigned int out_len = 0;
    SUCCESS(AES_Encrypt(&cx, scratch + header_len, &out_len, token_len + 16,
                        token, token_len));
    AES_DestroyContext(&cx, false);
  }
}

MEASURE(aes_gcm_fast) {
  uint8_t scratch[128];
  static const uint8_t gcm_H[16] = {0xe6, 0xad, 0x60, 0x0d, 0xdb, 0xbc,
                                    0xb2, 0x68, 0xc3, 0x32, 0x00, 0x49,
                                    0x99, 0x69, 0xa9, 0xad};

  gcmHashContext ghash_cx;
  SUCCESS(gcmHash_InitContext(&ghash_cx, gcm_H, false));

  // This does too much, but we'll amortise this cost.
  // It's really hard to initialize an AES key here so we let NSS do that for
  // us.
  CK_AES_CTR_PARAMS ctr_params = {.ulCounterBits = 32, .cb = {0}};
  AESContext aes_cx;
  SUCCESS(AES_InitContext(&aes_cx, retry_key, sizeof(retry_key),
                          (const uint8_t *)&ctr_params, NSS_AES_CTR, 1,
                          AES_BLOCK_SIZE));

  // Borrow the CTR context for the duration of the test.
  CTRContext ctr_cx;
  memcpy(&ctr_cx, aes_cx.worker_cx, sizeof(ctr_cx));

  const uint8_t *cursor = data;
  for (size_t i = 0; i < item_count; ++i) {
    // Lump the header and token together for this method.
    size_t header_len = *cursor++;
    size_t token_len = *cursor++;

    size_t odcid_len = *cursor++;
    const uint8_t *odcid = cursor;
    cursor += odcid_len;

    const uint8_t *header = cursor;
    cursor += header_len;
    const uint8_t *token = cursor;
    cursor += token_len;

    memcpy(scratch, header, header_len);

    // Reset the state of the CTR instance directly.
    // This direct access avoids having to rebuild the keys.
    memcpy(ctr_cx.counter, odcid, 8);
    static const uint8_t counter_reset[8] = {0, 0, 0, 0, 0, 0, 0, 1};
    memcpy(ctr_cx.counter + 8, counter_reset, 8);
    ctr_cx.bufPtr = AES_BLOCK_SIZE;

    unsigned int out_len = 0;
    SUCCESS(CTR_Update(&ctr_cx, scratch + header_len, &out_len, token_len,
                       token, token_len, AES_BLOCK_SIZE));

    SUCCESS(gcmHash_Reset(&ghash_cx, header, header_len));
    SUCCESS(gcmHash_Update(&ghash_cx, scratch + header_len, token_len));
    SUCCESS(gcmHash_Final(&ghash_cx, scratch + header_len + token_len, &out_len,
                          16));

    for (size_t j = 0; j < 16; ++j) {
      scratch[header_len + j] ^= tag_mask[j];
    }
  }

  AES_DestroyContext(&aes_cx, false);
}

void usage(const char *n) {
  fprintf(stderr, "Usage: %s [#iterations=%zd]\n", n, iterations);
  exit(2);
}

#define BENCHMARK(_name)                                                       \
  do {                                                                         \
    uint32_t t = measure_##_name();                                            \
    printf("%-12s\t%8" PRIu32 "\n", #_name ":", t);                            \
  } while (0)

int main(int argc, char **argv) {
  if (argc >= 2) {
    char *endptr;
    iterations = strtoull(argv[1], &endptr, 10);
    if (endptr - argv[1] != strlen(argv[1])) {
      usage(argv[0]);
    }
  }

  SUCCESS(BL_Init());
  if (!setup()) {
    fprintf(stderr, "Unable to setup: %d\n", errno);
    exit(1);
  }
  benchmark_floor = measure_calibrate();
  printf("Measuring best of %zd iterations\n", iterations);
  BENCHMARK(ghash);
  BENCHMARK(aes_gcm_slow);
  BENCHMARK(aes_gcm_fast);

  cleanup();
}
