#include "corpus.h"

static const char B32_ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
static const char B64_ALPHABET[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int alphabet_position(const char *alphabet, u32 span, char wanted) {
    for (u32 i = 0; i < span; i++) {
        if (alphabet[i] == wanted) {
            return (int)i;
        }
    }
    return -1;
}

u32 b32_encode(char *out, u32 capacity, const u8 *input, u32 length) {
    u32 written = 0;
    u32 accumulator = 0;
    u32 bits = 0;
    for (u32 i = 0; i < length; i++) {
        accumulator = (accumulator << 8) | input[i];
        bits += 8;
        while (bits >= 5) {
            if (written >= capacity) {
                return written;
            }
            bits -= 5;
            out[written++] = B32_ALPHABET[(accumulator >> bits) & 0x1fu];
        }
    }
    if (bits > 0 && written < capacity) {
        out[written++] = B32_ALPHABET[(accumulator << (5 - bits)) & 0x1fu];
    }
    while ((written % 8) != 0 && written < capacity) {
        out[written++] = '=';
    }
    return written;
}

u32 b32_decode(u8 *out, u32 capacity, const char *input, u32 length) {
    u32 written = 0;
    u32 accumulator = 0;
    u32 bits = 0;
    for (u32 i = 0; i < length; i++) {
        if (input[i] == '=') {
            break;
        }
        int position = alphabet_position(B32_ALPHABET, 32, input[i]);
        if (position < 0) {
            continue;
        }
        accumulator = (accumulator << 5) | (u32)position;
        bits += 5;
        if (bits >= 8) {
            if (written >= capacity) {
                return written;
            }
            bits -= 8;
            out[written++] = (u8)((accumulator >> bits) & 0xffu);
        }
    }
    return written;
}

u32 b64_encode(char *out, u32 capacity, const u8 *input, u32 length) {
    u32 written = 0;
    u32 i = 0;
    while (i + 2 < length) {
        u32 triple = ((u32)input[i] << 16) | ((u32)input[i + 1] << 8) | (u32)input[i + 2];
        if (written + 4 > capacity) {
            return written;
        }
        out[written++] = B64_ALPHABET[(triple >> 18) & 0x3fu];
        out[written++] = B64_ALPHABET[(triple >> 12) & 0x3fu];
        out[written++] = B64_ALPHABET[(triple >> 6) & 0x3fu];
        out[written++] = B64_ALPHABET[triple & 0x3fu];
        i += 3;
    }
    u32 tail = length - i;
    if (tail == 0 || written + 4 > capacity) {
        return written;
    }
    u32 triple = (u32)input[i] << 16;
    if (tail == 2) {
        triple |= (u32)input[i + 1] << 8;
    }
    out[written++] = B64_ALPHABET[(triple >> 18) & 0x3fu];
    out[written++] = B64_ALPHABET[(triple >> 12) & 0x3fu];
    out[written++] = tail == 2 ? B64_ALPHABET[(triple >> 6) & 0x3fu] : '=';
    out[written++] = '=';
    return written;
}

u32 b64_decode(u8 *out, u32 capacity, const char *input, u32 length) {
    u32 written = 0;
    u32 accumulator = 0;
    u32 bits = 0;
    for (u32 i = 0; i < length; i++) {
        if (input[i] == '=') {
            break;
        }
        int position = alphabet_position(B64_ALPHABET, 64, input[i]);
        if (position < 0) {
            continue;
        }
        accumulator = (accumulator << 6) | (u32)position;
        bits += 6;
        if (bits >= 8) {
            if (written >= capacity) {
                return written;
            }
            bits -= 8;
            out[written++] = (u8)((accumulator >> bits) & 0xffu);
        }
    }
    return written;
}

const char *codec_report(u32 encoded, u32 decoded, u32 original) {
    if (decoded != original) {
        return "the round trip lost bytes on the way back";
    }
    if (encoded == 0) {
        return "the encoder produced an empty block";
    }
    return "the round trip returned every byte it was given";
}

u64 corpus_main(u64 seed) {
    u8 raw[48];
    char text[128];
    u8 back[64];

    for (u32 i = 0; i < 48; i++) {
        raw[i] = (u8)(seed * 1099511628211ull + i * 251u);
    }

    u32 encoded32 = b32_encode(text, 128, raw, 48);
    u32 decoded32 = b32_decode(back, 64, text, encoded32);
    u32 encoded64 = b64_encode(text, 128, raw, 48);
    u32 decoded64 = b64_decode(back, 64, text, encoded64);
    const char *report = codec_report(encoded64, decoded64, 48);

    u64 total = (u64)encoded32 * 7u + (u64)decoded32 * 11u + (u64)encoded64 * 13u +
                (u64)decoded64 * 17u;
    for (u32 i = 0; i < decoded64 && i < 64; i++) {
        total = total * 33u + back[i];
    }
    for (const char *p = report; *p != 0; p++) {
        total ^= (u64)(u8)*p * 3u;
    }
    return total;
}
