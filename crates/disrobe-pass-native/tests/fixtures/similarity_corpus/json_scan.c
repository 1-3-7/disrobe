#include "corpus.h"

#define JSON_MAX_DEPTH 32

static int is_space(char value) {
    return value == ' ' || value == '\t' || value == '\n' || value == '\r';
}

static int is_digit(char value) {
    return value >= '0' && value <= '9';
}

u32 json_skip_space(const char *text, u32 length, u32 position) {
    while (position < length && is_space(text[position])) {
        position++;
    }
    return position;
}

i32 json_scan_string(const char *text, u32 length, u32 position) {
    if (position >= length || text[position] != '"') {
        return -1;
    }
    position++;
    while (position < length) {
        char current = text[position];
        if (current == '\\') {
            if (position + 1 >= length) {
                return -1;
            }
            position += 2;
            continue;
        }
        if (current == '"') {
            return (i32)(position + 1);
        }
        if ((u8)current < 0x20) {
            return -1;
        }
        position++;
    }
    return -1;
}

i32 json_scan_number(const char *text, u32 length, u32 position) {
    u32 start = position;
    if (position < length && text[position] == '-') {
        position++;
    }
    while (position < length && is_digit(text[position])) {
        position++;
    }
    if (position < length && text[position] == '.') {
        position++;
        while (position < length && is_digit(text[position])) {
            position++;
        }
    }
    if (position < length && (text[position] == 'e' || text[position] == 'E')) {
        position++;
        if (position < length && (text[position] == '+' || text[position] == '-')) {
            position++;
        }
        while (position < length && is_digit(text[position])) {
            position++;
        }
    }
    return position == start ? -1 : (i32)position;
}

i32 json_scan_literal(const char *text, u32 length, u32 position) {
    static const char *words[3] = {"true", "false", "null"};
    for (u32 word = 0; word < 3; word++) {
        u32 span = 0;
        while (words[word][span] != 0) {
            span++;
        }
        if (position + span > length) {
            continue;
        }
        u32 matched = 0;
        while (matched < span && text[position + matched] == words[word][matched]) {
            matched++;
        }
        if (matched == span) {
            return (i32)(position + span);
        }
    }
    return -1;
}

i32 json_validate(const char *text, u32 length) {
    char stack[JSON_MAX_DEPTH];
    u32 depth = 0;
    u32 position = json_skip_space(text, length, 0);
    u32 deepest = 0;

    while (position < length) {
        char current = text[position];
        if (current == '{' || current == '[') {
            if (depth >= JSON_MAX_DEPTH) {
                return -1;
            }
            stack[depth++] = current;
            if (depth > deepest) {
                deepest = depth;
            }
            position++;
        } else if (current == '}' || current == ']') {
            if (depth == 0) {
                return -1;
            }
            char opener = stack[--depth];
            if ((current == '}' && opener != '{') || (current == ']' && opener != '[')) {
                return -1;
            }
            position++;
        } else if (current == '"') {
            i32 next = json_scan_string(text, length, position);
            if (next < 0) {
                return -1;
            }
            position = (u32)next;
        } else if (current == ',' || current == ':') {
            position++;
        } else if (is_digit(current) || current == '-') {
            i32 next = json_scan_number(text, length, position);
            if (next < 0) {
                return -1;
            }
            position = (u32)next;
        } else {
            i32 next = json_scan_literal(text, length, position);
            if (next < 0) {
                return -1;
            }
            position = (u32)next;
        }
        position = json_skip_space(text, length, position);
    }
    return depth == 0 ? (i32)deepest : -1;
}

const char *json_diagnosis(i32 outcome) {
    if (outcome < 0) {
        return "the document broke its own grammar before the end";
    }
    if (outcome > 8) {
        return "the document nested deeper than the reader expects";
    }
    return "the document closed every container it opened";
}

u64 corpus_main(u64 seed) {
    static const char sample[] =
        "{\"name\":\"disrobe\",\"tags\":[\"static\",\"native\"],\"depth\":{\"a\":{\"b\":[1,-2.5,3e4]}},"
        "\"ok\":true,\"missing\":null}";
    u32 length = 0;
    while (sample[length] != 0) {
        length++;
    }

    i32 outcome = json_validate(sample, length);
    i32 truncated = json_validate(sample, length - (u32)(seed % 7u) - 1u);
    const char *diagnosis = json_diagnosis(outcome);

    u64 total = (u64)(outcome + 3) * 7919u + (u64)(truncated + 3) * 104729u;
    for (const char *p = diagnosis; *p != 0; p++) {
        total = total * 31u + (u64)(u8)*p;
    }
    return total;
}
