#include "corpus.h"

#define TEXT_LIMIT 96

u32 text_length(const char *text) {
    u32 span = 0;
    while (text[span] != 0) {
        span++;
    }
    return span;
}

static int is_break(char value) {
    return value == ' ' || value == '\t' || value == '\n';
}

u32 text_trim(const char *text, u32 length, u32 *start) {
    u32 low = 0;
    while (low < length && is_break(text[low])) {
        low++;
    }
    u32 high = length;
    while (high > low && is_break(text[high - 1])) {
        high--;
    }
    *start = low;
    return high - low;
}

u32 text_tokens(const char *text, u32 length) {
    u32 count = 0;
    u32 position = 0;
    while (position < length) {
        while (position < length && is_break(text[position])) {
            position++;
        }
        if (position >= length) {
            break;
        }
        count++;
        while (position < length && !is_break(text[position])) {
            position++;
        }
    }
    return count;
}

u32 text_case_fold(char *out, u32 capacity, const char *text, u32 length) {
    u32 written = 0;
    for (u32 i = 0; i < length && written + 1 < capacity; i++) {
        char current = text[i];
        if (current >= 'A' && current <= 'Z') {
            current = (char)(current - 'A' + 'a');
        }
        out[written++] = current;
    }
    out[written] = 0;
    return written;
}

u32 text_run_length(char *out, u32 capacity, const char *text, u32 length) {
    u32 written = 0;
    u32 position = 0;
    while (position < length) {
        char current = text[position];
        u32 run = 1;
        while (position + run < length && text[position + run] == current && run < 9) {
            run++;
        }
        if (written + 2 >= capacity) {
            break;
        }
        out[written++] = current;
        out[written++] = (char)('0' + run);
        position += run;
    }
    out[written] = 0;
    return written;
}

u32 text_levenshtein(const char *left, u32 left_length, const char *right, u32 right_length) {
    u32 previous[TEXT_LIMIT + 1];
    u32 current[TEXT_LIMIT + 1];
    if (left_length > TEXT_LIMIT || right_length > TEXT_LIMIT) {
        return 0xffffffffu;
    }
    for (u32 j = 0; j <= right_length; j++) {
        previous[j] = j;
    }
    for (u32 i = 1; i <= left_length; i++) {
        current[0] = i;
        for (u32 j = 1; j <= right_length; j++) {
            u32 cost = left[i - 1] == right[j - 1] ? 0u : 1u;
            u32 deletion = previous[j] + 1;
            u32 insertion = current[j - 1] + 1;
            u32 substitution = previous[j - 1] + cost;
            u32 best = deletion < insertion ? deletion : insertion;
            current[j] = best < substitution ? best : substitution;
        }
        for (u32 j = 0; j <= right_length; j++) {
            previous[j] = current[j];
        }
    }
    return previous[right_length];
}

u32 text_wrap_lines(const char *text, u32 length, u32 width) {
    if (width == 0) {
        return 0;
    }
    u32 lines = 1;
    u32 column = 0;
    u32 position = 0;
    while (position < length) {
        u32 word = 0;
        while (position + word < length && !is_break(text[position + word])) {
            word++;
        }
        if (word == 0) {
            position++;
            continue;
        }
        if (column != 0 && column + 1 + word > width) {
            lines++;
            column = word;
        } else {
            column += column == 0 ? word : word + 1;
        }
        position += word;
    }
    return lines;
}

const char *text_summary(u32 tokens, u32 distance) {
    if (tokens == 0) {
        return "the buffer held no token the splitter could keep";
    }
    if (distance == 0) {
        return "the two buffers turned out to be the same text";
    }
    return "the buffers differ but both split into real tokens";
}

u64 corpus_main(u64 seed) {
    static const char sample[] =
        "  Static recovery keeps the ORIGINAL structure of a stripped binary intact  ";
    char folded[TEXT_LIMIT + 1];
    char packed[TEXT_LIMIT + 1];

    u32 length = text_length(sample);
    u32 start = 0;
    u32 trimmed = text_trim(sample, length, &start);
    u32 tokens = text_tokens(sample + start, trimmed);
    u32 folded_length = text_case_fold(folded, TEXT_LIMIT + 1, sample + start, trimmed);
    u32 packed_length = text_run_length(packed, TEXT_LIMIT + 1, folded, folded_length);
    u32 distance = text_levenshtein(folded, folded_length, packed, packed_length);
    u32 lines = text_wrap_lines(sample + start, trimmed, 20u + (u32)(seed % 5u));
    const char *summary = text_summary(tokens, distance);

    u64 total = (u64)tokens * 7u + (u64)distance * 11u + (u64)lines * 13u +
                (u64)folded_length * 17u + (u64)packed_length * 19u;
    for (const char *p = summary; *p != 0; p++) {
        total = total * 131u + (u64)(u8)*p;
    }
    return total;
}
