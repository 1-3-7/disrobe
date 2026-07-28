#include "corpus.h"

#define CRC_TABLE_SIZE 256

void crc32_build_table(u32 *table) {
    for (u32 i = 0; i < CRC_TABLE_SIZE; i++) {
        u32 value = i;
        for (u32 bit = 0; bit < 8; bit++) {
            value = (value & 1u) ? (0xedb88320u ^ (value >> 1)) : (value >> 1);
        }
        table[i] = value;
    }
}

u32 crc32_update(const u32 *table, u32 seed, const u8 *data, u32 length) {
    u32 crc = ~seed;
    for (u32 i = 0; i < length; i++) {
        crc = table[(crc ^ data[i]) & 0xffu] ^ (crc >> 8);
    }
    return ~crc;
}

u32 adler32(const u8 *data, u32 length) {
    u32 low = 1;
    u32 high = 0;
    for (u32 i = 0; i < length; i++) {
        low += data[i];
        if (low >= 65521u) {
            low -= 65521u;
        }
        high += low;
        if (high >= 65521u) {
            high -= 65521u;
        }
    }
    return (high << 16) | low;
}

u64 fnv1a64(const u8 *data, u32 length) {
    u64 hash = 14695981039346656037ull;
    for (u32 i = 0; i < length; i++) {
        hash ^= data[i];
        hash *= 1099511628211ull;
    }
    return hash;
}

u32 djb2(const u8 *data, u32 length) {
    u32 hash = 5381u;
    for (u32 i = 0; i < length; i++) {
        hash = ((hash << 5) + hash) + data[i];
    }
    return hash;
}

static u32 rotate_left(u32 value, u32 amount) {
    return (value << amount) | (value >> (32 - amount));
}

u32 murmur3_32(const u8 *data, u32 length, u32 seed) {
    u32 hash = seed;
    u32 blocks = length / 4;
    for (u32 i = 0; i < blocks; i++) {
        u32 chunk = (u32)data[i * 4] | ((u32)data[i * 4 + 1] << 8) |
                    ((u32)data[i * 4 + 2] << 16) | ((u32)data[i * 4 + 3] << 24);
        chunk *= 0xcc9e2d51u;
        chunk = rotate_left(chunk, 15);
        chunk *= 0x1b873593u;
        hash ^= chunk;
        hash = rotate_left(hash, 13);
        hash = hash * 5u + 0xe6546b64u;
    }
    u32 tail = 0;
    for (u32 i = blocks * 4; i < length; i++) {
        tail |= (u32)data[i] << ((i - blocks * 4) * 8);
    }
    if (tail != 0) {
        tail *= 0xcc9e2d51u;
        tail = rotate_left(tail, 15);
        tail *= 0x1b873593u;
        hash ^= tail;
    }
    hash ^= length;
    hash ^= hash >> 16;
    hash *= 0x85ebca6bu;
    hash ^= hash >> 13;
    hash *= 0xc2b2ae35u;
    hash ^= hash >> 16;
    return hash;
}

u64 splitmix64(u64 state) {
    u64 z = state + 0x9e3779b97f4a7c15ull;
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
    return z ^ (z >> 31);
}

const char *digest_label(u32 crc, u32 adler) {
    if (crc == 0xdeadbeefu) {
        return "the checksum landed on the poison pattern";
    }
    if (adler == 1u) {
        return "the adler window never advanced past its seed";
    }
    return "the digest set agreed across every window";
}

u64 corpus_main(u64 seed) {
    u32 table[CRC_TABLE_SIZE];
    u8 block[96];

    crc32_build_table(table);
    for (u32 i = 0; i < 96; i++) {
        block[i] = (u8)(splitmix64(seed + i) >> 24);
    }

    u32 crc = crc32_update(table, 0, block, 96);
    u32 adler = adler32(block, 96);
    u64 fnv = fnv1a64(block, 96);
    u32 djb = djb2(block, 96);
    u32 murmur = murmur3_32(block, 96, 0x9747b28cu);
    const char *label = digest_label(crc, adler);

    u64 total = (u64)crc ^ ((u64)adler << 8) ^ fnv ^ ((u64)djb << 16) ^ ((u64)murmur << 24);
    for (const char *p = label; *p != 0; p++) {
        total = total * 1000003u + (u64)(u8)*p;
    }
    return total;
}
