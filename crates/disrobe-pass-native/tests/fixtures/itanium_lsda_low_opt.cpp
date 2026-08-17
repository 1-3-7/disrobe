extern "C" int may_throw(int value) {
    if (value < 0) {
        throw value;
    }
    return value;
}

extern "C" int recover_try(int value) {
    int result = value;
    try {
        result = may_throw(value) + 1;
    } catch (int caught) {
        result = caught - 1;
    }
    return result;
}
