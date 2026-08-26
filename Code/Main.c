#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <strings.h>

#define CHUNK_SIZE    65536
#define TAG_LEN       16
#define NONCE_LEN     12
#define KEY_LEN       32
#define BLOCK_SIZE    32
#define SHA256_LEN    32
#define SOF_MARKER    "SOF"
#define EOF_MARKER    "EOF"
#define DEFAULT_MULTILINE_MAX (1024 * 1024)
#define ABSOLUTE_MULTILINE_MAX (1024UL * 1024 * 1024)

static bool g_debug_mode = false;
static size_t g_multiline_max = DEFAULT_MULTILINE_MAX;

static void secure_zero(void *ptr, size_t len) {
#if defined(__STDC_LIB_EXT1__) || defined(_WIN32)
    memset_s(ptr, len, 0, len);
#elif defined(__linux__) || defined(__APPLE__)
    explicit_bzero(ptr, len);
#else
    volatile unsigned char *vp = (volatile unsigned char *)ptr;
    while (len--) *vp++ = 0;
#endif
}

static void flush_line(void) {
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}
}

static void prompt(const char *msg) {
    printf("%s", msg);
    fflush(stdout);
}

static void debug_print(const char *msg) {
    if (g_debug_mode) printf("[Debug] %s\n", msg);
}

static bool safe_getline(char *buf, size_t size) {
    if (!fgets(buf, size, stdin)) return false;
    size_t len = strcspn(buf, "\n");
    if (buf[len] == '\n') {
        buf[len] = '\0';
    } else {
        buf[len] = '\0';
        flush_line();
    }
    return true;
}

static char *read_input(const char *first_line, size_t *out_len) {
    if (strcmp(first_line, SOF_MARKER) == 0) {
        char *buf = malloc(g_multiline_max);
        if (!buf) return NULL;
        size_t total = 0;
        char mline[65536];

        while (fgets(mline, sizeof(mline), stdin)) {
            size_t llen = strlen(mline);

            size_t trimmed = llen;
            while (trimmed > 0 &&
                   (mline[trimmed - 1] == '\n' || mline[trimmed - 1] == '\r'))
                trimmed--;

            if (trimmed == 3 && memcmp(mline, EOF_MARKER, 3) == 0) {
                buf[total] = '\0';
                *out_len = total;
                return buf;
            }

            if (total + llen >= g_multiline_max - 1) {
                free(buf);
                return NULL;
            }
            memcpy(buf + total, mline, llen);
            total += llen;
        }
        free(buf);
        return NULL;
    } else {
        size_t len = strlen(first_line);
        char *buf = malloc(len + 1);
        if (!buf) return NULL;
        memcpy(buf, first_line, len + 1);
        *out_len = len;
        return buf;
    }
}

static size_t strip_non_hex(char *s, size_t len) {
    size_t w = 0;
    for (size_t r = 0; r < len; r++) {
        char c = s[r];
        if ((c >= '0' && c <= '9') ||
            (c >= 'a' && c <= 'f') ||
            (c >= 'A' && c <= 'F'))
            s[w++] = c;
    }
    s[w] = '\0';
    return w;
}

static void pack_be_u16(uint8_t *dst, uint16_t v) {
    dst[0] = (uint8_t)(v >> 8);
    dst[1] = (uint8_t)(v);
}

static void pack_be_u32(uint8_t *dst, uint32_t v) {
    dst[0] = (uint8_t)(v >> 24);
    dst[1] = (uint8_t)(v >> 16);
    dst[2] = (uint8_t)(v >> 8);
    dst[3] = (uint8_t)(v);
}

static uint32_t unpack_be_u32(const uint8_t *src) {
    return ((uint32_t)src[0] << 24) | ((uint32_t)src[1] << 16) |
           ((uint32_t)src[2] << 8)  | (uint32_t)src[3];
}

static void pack_le_u64(uint8_t *dst, uint64_t v) {
    for (int i = 0; i < 8; i++) dst[i] = (uint8_t)(v >> (i * 8));
}

static int hkdf_extract(const uint8_t *salt, size_t salt_len,
                        const uint8_t *ikm, size_t ikm_len,
                        uint8_t prk[SHA256_LEN]) {
    uint8_t default_salt[SHA256_LEN];
    if (!salt || salt_len == 0) {
        memset(default_salt, 0, SHA256_LEN);
        salt = default_salt;
        salt_len = SHA256_LEN;
    }
    unsigned int out_len = 0;
    if (!HMAC(EVP_sha256(), salt, (int)salt_len,
              ikm, ikm_len, prk, &out_len))
        return -1;
    return 0;
}

static int hkdf_expand(const uint8_t prk[SHA256_LEN],
                       const uint8_t *info, size_t info_len,
                       uint8_t *okm, size_t length) {
    if (length > 255 * SHA256_LEN) return -1;

    uint8_t t_prev[SHA256_LEN];
    size_t t_prev_len = 0;
    uint8_t counter = 1;
    size_t written = 0;

    while (written < length) {
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (!ctx) return -1;

        uint8_t hmac_input[SHA256_LEN + 256 + 1];
        size_t hmac_input_len = 0;

        if (t_prev_len > 0) {
            memcpy(hmac_input, t_prev, t_prev_len);
            hmac_input_len += t_prev_len;
        }
        if (info_len > 0 && info_len <= 256) {
            memcpy(hmac_input + hmac_input_len, info, info_len);
            hmac_input_len += info_len;
        }
        hmac_input[hmac_input_len++] = counter;

        unsigned int out_len = 0;
        if (!HMAC(EVP_sha256(), prk, SHA256_LEN,
                  hmac_input, hmac_input_len, t_prev, &out_len)) {
            EVP_MD_CTX_free(ctx);
            return -1;
        }
        EVP_MD_CTX_free(ctx);
        t_prev_len = SHA256_LEN;

        size_t to_copy = length - written;
        if (to_copy > SHA256_LEN) to_copy = SHA256_LEN;
        memcpy(okm + written, t_prev, to_copy);
        written += to_copy;
        counter++;
    }
    secure_zero(t_prev, sizeof(t_prev));
    return 0;
}

typedef struct {
    uint8_t rk1[KEY_LEN];
    uint8_t rk2[KEY_LEN];
    uint8_t mac_key[KEY_LEN];
    uint8_t stream_key[KEY_LEN];
} SessionKeys;

static int session_keys_init(SessionKeys *sk,
                             const uint8_t master_key[KEY_LEN],
                             const uint8_t base_nonce[NONCE_LEN]) {
    uint8_t prk[SHA256_LEN];
    if (hkdf_extract(base_nonce, NONCE_LEN, master_key, KEY_LEN, prk) != 0)
        return -1;

    uint8_t info1[16];
    size_t info1_len = 0;
    memcpy(info1, "feistel_rk_v1|", 14); info1_len = 14;
    pack_be_u16(info1 + info1_len, 1); info1_len += 2;
    if (hkdf_expand(prk, info1, info1_len, sk->rk1, KEY_LEN) != 0) goto fail;

    pack_be_u16(info1 + 14, 2);
    if (hkdf_expand(prk, info1, info1_len, sk->rk2, KEY_LEN) != 0) goto fail;

    if (hkdf_expand(prk, (const uint8_t *)"aead_mac_v1", 11,
                    sk->mac_key, KEY_LEN) != 0) goto fail;

    if (hkdf_expand(prk, (const uint8_t *)"stream_chunk_key_v1", 19,
                    sk->stream_key, KEY_LEN) != 0) goto fail;

    secure_zero(prk, sizeof(prk));
    return 0;
fail:
    secure_zero(prk, sizeof(prk));
    secure_zero(sk, sizeof(*sk));
    return -1;
}

static void session_keys_zeroize(SessionKeys *sk) {
    secure_zero(sk, sizeof(*sk));
}

static void feistel_block(const uint8_t rk1[KEY_LEN],
                          const uint8_t rk2[KEY_LEN],
                          const uint8_t chunk_nonce[NONCE_LEN],
                          uint32_t block_counter,
                          uint8_t out[BLOCK_SIZE]) {
    uint8_t input_block[BLOCK_SIZE];
    memcpy(input_block, chunk_nonce, NONCE_LEN);
    pack_be_u32(input_block + NONCE_LEN, block_counter);
    memset(input_block + NONCE_LEN + 4, 0, 16);

    uint8_t *l0 = input_block;
    uint8_t *r0 = input_block + 16;

    uint8_t f1_buf[11 + 16];
    memcpy(f1_buf, "feistel_r1|", 11);
    memcpy(f1_buf + 11, r0, 16);

    uint8_t f1_full[SHA256_LEN];
    unsigned int f1_len = 0;
    HMAC(EVP_sha256(), rk1, KEY_LEN, f1_buf, sizeof(f1_buf), f1_full, &f1_len);

    uint8_t l1[16], r1[16];
    for (int i = 0; i < 16; i++) l1[i] = l0[i] ^ f1_full[i];
    memcpy(r1, r0, 16);

    uint8_t f2_buf[11 + 16];
    memcpy(f2_buf, "feistel_r2|", 11);
    memcpy(f2_buf + 11, l1, 16);

    uint8_t f2_full[SHA256_LEN];
    unsigned int f2_len = 0;
    HMAC(EVP_sha256(), rk2, KEY_LEN, f2_buf, sizeof(f2_buf), f2_full, &f2_len);

    memcpy(out, l1, 16);
    for (int i = 0; i < 16; i++) out[16 + i] = r1[i] ^ f2_full[i];

    secure_zero(f1_full, sizeof(f1_full));
    secure_zero(f2_full, sizeof(f2_full));
}

static int feistel_stream(const SessionKeys *keys,
                          const uint8_t chunk_nonce[NONCE_LEN],
                          size_t data_len,
                          uint8_t *keystream) {
    size_t generated = 0;
    uint32_t block_counter = 0;

    while (generated < data_len) {
        uint8_t ks_block[BLOCK_SIZE];
        feistel_block(keys->rk1, keys->rk2, chunk_nonce, block_counter, ks_block);

        size_t to_copy = data_len - generated;
        if (to_copy > BLOCK_SIZE) to_copy = BLOCK_SIZE;
        memcpy(keystream + generated, ks_block, to_copy);
        generated += to_copy;
        block_counter++;

        secure_zero(ks_block, sizeof(ks_block));
    }
    return 0;
}

static int derive_chunk_nonce(const uint8_t stream_key[KEY_LEN],
                              uint32_t chunk_index,
                              bool is_final,
                              uint8_t nonce_out[NONCE_LEN]) {
    uint8_t context[15 + 4 + 1];
    memcpy(context, "chunk_nonce_v1|", 15);
    pack_be_u32(context + 15, chunk_index);
    context[19] = is_final ? 0x01 : 0x00;

    uint8_t full_hash[SHA256_LEN];
    unsigned int hlen = 0;
    if (!HMAC(EVP_sha256(), stream_key, KEY_LEN,
              context, sizeof(context), full_hash, &hlen))
        return -1;

    memcpy(nonce_out, full_hash, NONCE_LEN);
    secure_zero(full_hash, sizeof(full_hash));
    return 0;
}

static int compute_tag(const uint8_t mac_key[KEY_LEN],
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *ct, size_t ct_len,
                       uint8_t tag[TAG_LEN]) {
    size_t aad_padded = aad_len + ((16 - (aad_len % 16)) % 16);
    size_t ct_padded  = ct_len  + ((16 - (ct_len  % 16)) % 16);
    size_t total = aad_padded + ct_padded + 16;

    uint8_t *mac_input = malloc(total);
    if (!mac_input) return -1;

    size_t pos = 0;
    if (aad_len > 0) memcpy(mac_input + pos, aad, aad_len);
    pos += aad_len;
    size_t aad_rem = aad_len % 16;
    if (aad_rem != 0) { memset(mac_input + pos, 0, 16 - aad_rem); pos += 16 - aad_rem; }

    if (ct_len > 0) memcpy(mac_input + pos, ct, ct_len);
    pos += ct_len;
    size_t ct_rem = ct_len % 16;
    if (ct_rem != 0) { memset(mac_input + pos, 0, 16 - ct_rem); pos += 16 - ct_rem; }

    pack_le_u64(mac_input + pos, (uint64_t)aad_len); pos += 8;
    pack_le_u64(mac_input + pos, (uint64_t)ct_len);  pos += 8;

    uint8_t full_tag[SHA256_LEN];
    unsigned int tlen = 0;
    int rc = 0;
    if (!HMAC(EVP_sha256(), mac_key, KEY_LEN,
              mac_input, total, full_tag, &tlen))
        rc = -1;
    else
        memcpy(tag, full_tag, TAG_LEN);

    secure_zero(full_tag, sizeof(full_tag));
    secure_zero(mac_input, total);
    free(mac_input);
    return rc;
}

static bool verify_tag(const uint8_t mac_key[KEY_LEN],
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *ct, size_t ct_len,
                       const uint8_t expected[TAG_LEN]) {
    uint8_t computed[TAG_LEN];
    if (compute_tag(mac_key, aad, aad_len, ct, ct_len, computed) != 0)
        return false;
    bool ok = (CRYPTO_memcmp(computed, expected, TAG_LEN) == 0);
    secure_zero(computed, sizeof(computed));
    return ok;
}

static uint8_t *encrypt_data(const uint8_t master_key[KEY_LEN],
                             const uint8_t base_nonce[NONCE_LEN],
                             const uint8_t *plaintext, size_t pt_len,
                             const uint8_t *aad, size_t aad_len,
                             size_t *out_len) {
    SessionKeys keys;
    if (session_keys_init(&keys, master_key, base_nonce) != 0) return NULL;

    uint32_t num_chunks = (uint32_t)((pt_len + CHUNK_SIZE - 1) / CHUNK_SIZE);
    if (num_chunks == 0) num_chunks = 1;

    size_t header_len = NONCE_LEN + 4;
    size_t total = header_len;
    for (uint32_t i = 0; i < num_chunks; i++) {
        size_t chunk_pt_len = (i < num_chunks - 1) ? CHUNK_SIZE
                              : (pt_len - (size_t)i * CHUNK_SIZE);
        total += chunk_pt_len + TAG_LEN;
    }

    uint8_t *output = malloc(total);
    if (!output) { session_keys_zeroize(&keys); return NULL; }

    memcpy(output, base_nonce, NONCE_LEN);
    pack_be_u32(output + NONCE_LEN, num_chunks);

    size_t offset = header_len;
    for (uint32_t i = 0; i < num_chunks; i++) {
        size_t start = (size_t)i * CHUNK_SIZE;
        size_t chunk_pt_len = (i < num_chunks - 1) ? CHUNK_SIZE
                              : (pt_len - start);
        bool is_final = (i == num_chunks - 1);

        uint8_t chunk_nonce[NONCE_LEN];
        derive_chunk_nonce(keys.stream_key, i, is_final, chunk_nonce);

        uint8_t *ks = malloc(chunk_pt_len);
        if (!ks) { free(output); session_keys_zeroize(&keys); return NULL; }
        feistel_stream(&keys, chunk_nonce, chunk_pt_len, ks);

        uint8_t *chunk_ct = output + offset;
        for (size_t j = 0; j < chunk_pt_len; j++)
            chunk_ct[j] = plaintext[start + j] ^ ks[j];
        secure_zero(ks, chunk_pt_len);
        free(ks);

        uint8_t *tag_ptr = output + offset + chunk_pt_len;
        compute_tag(keys.mac_key, aad, aad_len, chunk_ct, chunk_pt_len, tag_ptr);

        offset += chunk_pt_len + TAG_LEN;
    }

    *out_len = total;
    session_keys_zeroize(&keys);
    return output;
}

static uint8_t *decrypt_data(const uint8_t master_key[KEY_LEN],
                             const uint8_t base_nonce[NONCE_LEN],
                             const uint8_t *pkg, size_t pkg_len,
                             const uint8_t *aad, size_t aad_len,
                             size_t *pt_len) {
    if (pkg_len < NONCE_LEN + 4) return NULL;

    const uint8_t *received_nonce = pkg;
    uint32_t num_chunks = unpack_be_u32(pkg + NONCE_LEN);

    if (memcmp(received_nonce, base_nonce, NONCE_LEN) != 0) return NULL;

    SessionKeys keys;
    if (session_keys_init(&keys, master_key, received_nonce) != 0) return NULL;

    size_t offset = NONCE_LEN + 4;
    size_t total_pt = 0;

    for (uint32_t i = 0; i < num_chunks; i++) {
        size_t remaining = pkg_len - offset;
        if (remaining < TAG_LEN) goto fail;

        size_t chunk_ct_len;
        if (i < num_chunks - 1)
            chunk_ct_len = CHUNK_SIZE;
        else
            chunk_ct_len = remaining - TAG_LEN;

        if (offset + chunk_ct_len + TAG_LEN > pkg_len) goto fail;

        const uint8_t *chunk_ct  = pkg + offset;
        const uint8_t *recv_tag  = pkg + offset + chunk_ct_len;

        if (!verify_tag(keys.mac_key, aad, aad_len,
                        chunk_ct, chunk_ct_len, recv_tag))
            goto fail;

        total_pt += chunk_ct_len;
        offset += chunk_ct_len + TAG_LEN;
    }

    uint8_t *plaintext = malloc(total_pt > 0 ? total_pt : 1);
    if (!plaintext) goto fail;

    offset = NONCE_LEN + 4;
    size_t pt_offset = 0;

    for (uint32_t i = 0; i < num_chunks; i++) {
        size_t remaining = pkg_len - offset;
        size_t chunk_ct_len = (i < num_chunks - 1) ? CHUNK_SIZE
                              : (remaining - TAG_LEN);
        bool is_final = (i == num_chunks - 1);

        uint8_t chunk_nonce[NONCE_LEN];
        derive_chunk_nonce(keys.stream_key, i, is_final, chunk_nonce);

        const uint8_t *chunk_ct = pkg + offset;

        uint8_t *ks = malloc(chunk_ct_len);
        if (!ks) { free(plaintext); goto fail; }
        feistel_stream(&keys, chunk_nonce, chunk_ct_len, ks);

        for (size_t j = 0; j < chunk_ct_len; j++)
            plaintext[pt_offset + j] = chunk_ct[j] ^ ks[j];
        secure_zero(ks, chunk_ct_len);
        free(ks);

        pt_offset += chunk_ct_len;
        offset += chunk_ct_len + TAG_LEN;
    }

    *pt_len = total_pt;
    session_keys_zeroize(&keys);
    return plaintext;

fail:
    session_keys_zeroize(&keys);
    return NULL;
}

static void print_hex(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) printf("%02x", data[i]);
}

static bool hex_to_bytes(const char *hex, uint8_t *out, size_t expected_len) {
    size_t hex_len = strlen(hex);
    if (hex_len != expected_len * 2) return false;
    for (size_t i = 0; i < expected_len; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return false;
        out[i] = (uint8_t)byte;
    }
    return true;
}

static char *bytes_to_hex_alloc(const uint8_t *data, size_t len) {
    char *hex = malloc(len * 2 + 1);
    if (!hex) return NULL;
    for (size_t i = 0; i < len; i++) sprintf(hex + i * 2, "%02x", data[i]);
    hex[len * 2] = '\0';
    return hex;
}

static void print_session(const uint8_t master_key[KEY_LEN],
                          const uint8_t nonce[NONCE_LEN]) {
    printf("\n[Current Session]\n");
    printf("  Master Key : "); print_hex(master_key, KEY_LEN); printf("\n");
    printf("  Next Nonce : "); print_hex(nonce, NONCE_LEN);
    printf(" (will be embedded in next encryption)\n");
    printf("  Key Size   : %d bits\n", KEY_LEN * 8);
    printf("  Chunk Size : %d bytes (%d KiB)\n", CHUNK_SIZE, CHUNK_SIZE / 1024);
    printf("  Tag Length : %d bytes (%d bits)\n", TAG_LEN, TAG_LEN * 8);
    printf("  Block Size : %d bytes (Feistel)\n", BLOCK_SIZE);
}

static void settings_menu(void) {
    char sline[256];
    while (true) {
        printf("\n============================================================\n");
        printf("SETTINGS\n");
        printf("------------------------------------------------------------\n");
        printf("1. Debug mode    [%s]\n", g_debug_mode ? "ON " : "OFF");
        printf("2. Max multiline [%zu MiB]\n", g_multiline_max / (1024 * 1024));
        printf("3. Back\n");
        printf("============================================================\n");
        prompt("Settings [1-3]: ");

        if (!safe_getline(sline, sizeof(sline))) return;

        if (strcmp(sline, "1") == 0) {
            g_debug_mode = !g_debug_mode;
            printf("  Debug mode: %s\n", g_debug_mode ? "ON" : "OFF");

        } else if (strcmp(sline, "2") == 0) {
            size_t abs_max_mib = ABSOLUTE_MULTILINE_MAX / (1024 * 1024);
            printf("  Current: %zu MiB | Max allowed: %zu MiB\n",
                   g_multiline_max / (1024 * 1024), abs_max_mib);
            prompt("  New max multiline size (MiB): ");
            if (!safe_getline(sline, sizeof(sline))) return;

            size_t val = (size_t)strtoul(sline, NULL, 10);
            if (val == 0) {
                printf("  [ERROR] Must be at least 1 MiB.\n");
            } else if (val > abs_max_mib) {
                printf("  [ERROR] Exceeds cipher limit of %zu MiB.\n", abs_max_mib);
            } else {
                g_multiline_max = (size_t)val * 1024 * 1024;
                printf("  ✓ Max multiline set to %zu MiB (%zu bytes)\n",
                       val, g_multiline_max);
            }

        } else if (strcmp(sline, "3") == 0) {
            return;

        } else {
            printf("  Invalid option. Please select 1-3.\n");
        }
    }
}

int main(void) {
    uint8_t master_key[KEY_LEN];
    uint8_t nonce[NONCE_LEN];

    RAND_bytes(master_key, KEY_LEN);
    RAND_bytes(nonce, NONCE_LEN);

    printf("============================================================\n");
    print_session(master_key, nonce);

    char line[65536];

    while (true) {
        printf("\n------------------------------------------------------------\n");
        printf("  1. Encrypt a message\n");
        printf("  2. Decrypt a ciphertext (hex)\n");
        printf("  3. Show session data\n");
        printf("  4. Input master key (hex)\n");
        printf("  5. Settings\n");
        printf("  6. Exit\n");
        printf("------------------------------------------------------------\n");
        prompt("\nSelect option [1-6]: ");

        if (!safe_getline(line, sizeof(line))) break;

        if (strcmp(line, "1") == 0) {
            prompt("Enter plaintext (or SOF for multiline): ");
            if (!safe_getline(line, sizeof(line))) break;

            size_t pt_len = 0;
            char *pt_buf = read_input(line, &pt_len);
            if (!pt_buf) {
                printf("\n[ERROR] Failed to read plaintext.\n");
                continue;
            }

            prompt("Enter AAD (optional, Enter to skip, or SOF for multiline): ");
            if (!safe_getline(line, sizeof(line))) { free(pt_buf); break; }

            size_t aad_len = 0;
            char *aad_buf = read_input(line, &aad_len);
            if (!aad_buf) {
                printf("\n[ERROR] Failed to read AAD.\n");
                free(pt_buf);
                continue;
            }

            size_t ct_len = 0;
            uint8_t *ct = encrypt_data(master_key, nonce,
                                       (const uint8_t *)pt_buf, pt_len,
                                       (const uint8_t *)aad_buf, aad_len,
                                       &ct_len);
            if (!ct) {
                printf("\n[ERROR] Encryption failed.\n");
                free(pt_buf);
                free(aad_buf);
                continue;
            }

            uint32_t num_chunks = (uint32_t)((pt_len + CHUNK_SIZE - 1) / CHUNK_SIZE);
            if (num_chunks == 0) num_chunks = 1;

            printf("\n[Encryption Result]\n");
            printf("  Plaintext len : %zu bytes\n", pt_len);
            printf("  Chunks        : %u\n", num_chunks);
            printf("  Ciphertext len: %zu bytes\n", ct_len);
            printf("  Overhead      : %zu bytes\n", ct_len - pt_len);
            printf("  Nonce used    : "); print_hex(nonce, NONCE_LEN); printf("\n");
            printf("  CT (hex)      :\n    ");
            char *ct_hex = bytes_to_hex_alloc(ct, ct_len);
            printf("%s\n", ct_hex);
            free(ct_hex);

            size_t rt_len = 0;
            uint8_t *rt = decrypt_data(master_key, nonce, ct, ct_len,
                                       (const uint8_t *)aad_buf, aad_len, &rt_len);
            bool roundtrip_ok = (rt != NULL && rt_len == pt_len &&
                                 memcmp(rt, pt_buf, pt_len) == 0);
            printf("  Roundtrip OK  : %s\n", roundtrip_ok ? "true" : "false");

            if (roundtrip_ok) {
                RAND_bytes(nonce, NONCE_LEN);
                printf("  ✓ Nonce rotated → "); print_hex(nonce, NONCE_LEN); printf("\n");
            } else {
                printf("  ✗ Nonce NOT rotated (roundtrip failed)\n");
            }

            if (rt) { secure_zero(rt, rt_len); free(rt); }
            secure_zero(ct, ct_len);
            free(ct);
            secure_zero(pt_buf, pt_len);
            free(pt_buf);
            secure_zero(aad_buf, aad_len);
            free(aad_buf);

        } else if (strcmp(line, "2") == 0) {
            prompt("Enter ciphertext hex (or SOF for multiline): ");
            if (!safe_getline(line, sizeof(line))) break;

            size_t hex_raw_len = 0;
            char *hex_raw = read_input(line, &hex_raw_len);
            if (!hex_raw) {
                printf("\n[ERROR] Failed to read ciphertext.\n");
                continue;
            }

            size_t clean_len = strip_non_hex(hex_raw, hex_raw_len);

            prompt("Enter AAD (Enter for none, or SOF for multiline): ");
            if (!safe_getline(line, sizeof(line))) { free(hex_raw); break; }

            size_t aad_len = 0;
            char *aad_buf = read_input(line, &aad_len);
            if (!aad_buf) {
                printf("\n[ERROR] Failed to read AAD.\n");
                free(hex_raw);
                continue;
            }

            size_t ct_len = clean_len / 2;
            size_t min_len = NONCE_LEN + 4 + TAG_LEN;
            if (clean_len % 2 != 0 || ct_len < min_len) {
                printf("\n[ERROR] Ciphertext too short (%zu bytes). Minimum: %zu bytes.\n",
                       ct_len, min_len);
                free(hex_raw);
                free(aad_buf);
                continue;
            }

            uint8_t *ct = malloc(ct_len);
            if (!ct || !hex_to_bytes(hex_raw, ct, ct_len)) {
                printf("\n[ERROR] Invalid hex input.\n");
                free(hex_raw);
                free(aad_buf);
                free(ct);
                continue;
            }
            free(hex_raw);

            uint8_t extracted_nonce[NONCE_LEN];
            memcpy(extracted_nonce, ct, NONCE_LEN);
            uint32_t chunk_count = unpack_be_u32(ct + NONCE_LEN);

            char dbg[64]; snprintf(dbg, sizeof(dbg), "%u", chunk_count);
            debug_print(dbg);

            printf("\n[Decryption Info]\n");
            printf("  Extracted nonce : "); print_hex(extracted_nonce, NONCE_LEN); printf("\n");
            printf("  Chunk count     : %u\n", chunk_count);
            printf("  Using master key: "); print_hex(master_key, KEY_LEN); printf("\n");

            size_t pt_len = 0;
            uint8_t *pt = decrypt_data(master_key, extracted_nonce, ct, ct_len,
                                       (const uint8_t *)aad_buf, aad_len, &pt_len);
            if (pt) {
                printf("\n[Decryption Successful]\nOutput:\n");
                fwrite(pt, 1, pt_len, stdout);
                printf("\n");
                secure_zero(pt, pt_len);
                free(pt);
            } else {
                printf("\n[AUTHENTICATION FAILED]\n");
                printf("  Possible causes:\n");
                printf("    - Wrong master key\n");
                printf("    - Wrong or missing AAD\n");
                printf("    - Ciphertext tampered/truncated/reordered\n");
                printf("    - Corrupted hex input\n");
            }

            secure_zero(ct, ct_len);
            free(ct);
            secure_zero(aad_buf, aad_len);
            free(aad_buf);

        } else if (strcmp(line, "3") == 0) {
            print_session(master_key, nonce);
            printf("\n  Note: The 'Next Nonce' shown above will be embedded\n");
            printf("  into the next ciphertext produced by option 1.\n");
            printf("  Decrypt (option 2) extracts the nonce automatically\n");
            printf("  from the ciphertext header — no manual entry needed.\n");

        } else if (strcmp(line, "4") == 0) {
            printf("\n  Enter a 64-character hex string (32 bytes / 256 bits).\n");
            printf("  Enter 'random' to generate a new key + nonce.\n");
            prompt("\n  Master key (hex or 'random'): ");
            if (!safe_getline(line, sizeof(line))) break;

            if (strcasecmp(line, "random") == 0) {
                RAND_bytes(master_key, KEY_LEN);
                RAND_bytes(nonce, NONCE_LEN);
                printf("\n  [New random session generated]\n");
            } else {
                uint8_t new_key[KEY_LEN];
                if (!hex_to_bytes(line, new_key, KEY_LEN)) {
                    printf("\n  [ERROR] Key must be %d bytes (%d hex chars). Got %zu hex chars.\n",
                           KEY_LEN, KEY_LEN * 2, strlen(line));
                    continue;
                }
                memcpy(master_key, new_key, KEY_LEN);
                secure_zero(new_key, KEY_LEN);

                prompt("  Initial nonce (24 char hex or 'random'): ");
                if (!safe_getline(line, sizeof(line))) break;

                if (strcasecmp(line, "random") == 0) {
                    RAND_bytes(nonce, NONCE_LEN);
                } else {
                    uint8_t new_nonce[NONCE_LEN];
                    if (!hex_to_bytes(line, new_nonce, NONCE_LEN)) {
                        printf("\n  [ERROR] Nonce must be %d bytes (%d hex chars). Got %zu hex chars.\n",
                               NONCE_LEN, NONCE_LEN * 2, strlen(line));
                        continue;
                    }
                    memcpy(nonce, new_nonce, NONCE_LEN);
                    secure_zero(new_nonce, NONCE_LEN);
                }
                printf("\n  [Session updated]\n");
            }
            print_session(master_key, nonce);
            printf("\n  ⚠ Previous ciphertexts encrypted under a different key\n");
            printf("    will fail authentication. This is expected behavior.\n");

        } else if (strcmp(line, "5") == 0) {
            settings_menu();

        } else if (strcmp(line, "6") == 0) {
            break;

        } else {
            printf("Invalid option. Please select 1-6.\n");
        }
    }

    secure_zero(master_key, KEY_LEN);
    secure_zero(nonce, NONCE_LEN);
    printf("\nGoodbye.\n");
    return 0;
}
