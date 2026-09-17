#include "corpus.h"

#define MATRIX_ORDER 6

static u32 slot(u32 row, u32 column) {
    return row * MATRIX_ORDER + column;
}

void matrix_identity(i64 *out) {
    for (u32 row = 0; row < MATRIX_ORDER; row++) {
        for (u32 column = 0; column < MATRIX_ORDER; column++) {
            out[slot(row, column)] = row == column ? 1 : 0;
        }
    }
}

void matrix_multiply(i64 *out, const i64 *left, const i64 *right) {
    for (u32 row = 0; row < MATRIX_ORDER; row++) {
        for (u32 column = 0; column < MATRIX_ORDER; column++) {
            i64 total = 0;
            for (u32 step = 0; step < MATRIX_ORDER; step++) {
                total += left[slot(row, step)] * right[slot(step, column)];
            }
            out[slot(row, column)] = total;
        }
    }
}

void matrix_transpose(i64 *out, const i64 *input) {
    for (u32 row = 0; row < MATRIX_ORDER; row++) {
        for (u32 column = 0; column < MATRIX_ORDER; column++) {
            out[slot(column, row)] = input[slot(row, column)];
        }
    }
}

i64 matrix_trace(const i64 *input) {
    i64 total = 0;
    for (u32 row = 0; row < MATRIX_ORDER; row++) {
        total += input[slot(row, row)];
    }
    return total;
}

void matrix_minor(i64 *out, const i64 *input, u32 order, u32 skip_row, u32 skip_column) {
    u32 target = 0;
    for (u32 row = 0; row < order; row++) {
        if (row == skip_row) {
            continue;
        }
        for (u32 column = 0; column < order; column++) {
            if (column == skip_column) {
                continue;
            }
            out[target++] = input[row * MATRIX_ORDER + column];
        }
    }
    for (u32 row = order - 1; row > 0; row--) {
        for (u32 column = order - 1; column > 0; column--) {
            u32 from = (row - 1) * (order - 1) + (column - 1);
            u32 to = (row - 1) * MATRIX_ORDER + (column - 1);
            if (to != from) {
                out[to] = out[from];
            }
        }
    }
}

i64 matrix_determinant(const i64 *input, u32 order) {
    if (order == 1) {
        return input[0];
    }
    if (order == 2) {
        return input[0] * input[MATRIX_ORDER + 1] - input[1] * input[MATRIX_ORDER];
    }
    i64 sub[MATRIX_ORDER * MATRIX_ORDER];
    i64 total = 0;
    i64 sign = 1;
    for (u32 column = 0; column < order; column++) {
        matrix_minor(sub, input, order, 0, column);
        total += sign * input[column] * matrix_determinant(sub, order - 1);
        sign = -sign;
    }
    return total;
}

void matrix_power(i64 *out, const i64 *input, u32 exponent) {
    i64 accumulator[MATRIX_ORDER * MATRIX_ORDER];
    i64 scratch[MATRIX_ORDER * MATRIX_ORDER];
    matrix_identity(accumulator);
    for (u32 step = 0; step < exponent; step++) {
        matrix_multiply(scratch, accumulator, input);
        for (u32 i = 0; i < MATRIX_ORDER * MATRIX_ORDER; i++) {
            accumulator[i] = scratch[i];
        }
    }
    for (u32 i = 0; i < MATRIX_ORDER * MATRIX_ORDER; i++) {
        out[i] = accumulator[i];
    }
}

const char *matrix_shape(i64 determinant, i64 trace) {
    if (determinant == 0) {
        return "the matrix collapsed onto a lower dimension";
    }
    if (trace == 0) {
        return "the matrix carries a diagonal that cancels itself";
    }
    return "the matrix stayed invertible across the whole run";
}

u64 corpus_main(u64 seed) {
    i64 left[MATRIX_ORDER * MATRIX_ORDER];
    i64 right[MATRIX_ORDER * MATRIX_ORDER];
    i64 product[MATRIX_ORDER * MATRIX_ORDER];

    for (u32 row = 0; row < MATRIX_ORDER; row++) {
        for (u32 column = 0; column < MATRIX_ORDER; column++) {
            left[slot(row, column)] = (i64)((seed + row * 7u + column * 3u) % 11u) - 5;
            right[slot(row, column)] = (i64)((seed * 3u + row * 5u + column * 13u) % 9u) - 4;
        }
    }

    matrix_multiply(product, left, right);
    matrix_transpose(left, product);
    i64 trace = matrix_trace(left);
    i64 determinant = matrix_determinant(right, 4);
    matrix_power(product, left, 3);
    const char *shape = matrix_shape(determinant, trace);

    u64 total = (u64)trace * 1000003u + (u64)determinant;
    for (u32 i = 0; i < MATRIX_ORDER * MATRIX_ORDER; i++) {
        total = total * 31u + (u64)product[i];
    }
    for (const char *p = shape; *p != 0; p++) {
        total ^= (u64)(u8)*p;
    }
    return total;
}
