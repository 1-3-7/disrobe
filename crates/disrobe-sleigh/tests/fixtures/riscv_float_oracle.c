float riscv_float_add(float left, float right) {
    return left + right;
}

float riscv_float_div(float left, float right) {
    return left / right;
}

double riscv_double_mix(double left, double right, double addend) {
    return left * right + addend;
}

int riscv_float_compare(float left, float right) {
    return left <= right;
}

double riscv_widen(float value) {
    return value;
}

float riscv_narrow(double value) {
    return value;
}

float riscv_load_float(const float *values) {
    return values[3];
}

void riscv_store_double(double *values, double value) {
    values[2] = value;
}

int riscv_float_to_int(float value) {
    return (int)value;
}

float riscv_int_to_float(int value) {
    return value;
}
