int disrobe_bigobj_probe(int value) { return value * 3 + 1; }
int disrobe_bigobj_second(int value) { return value ^ 0x5a5a; }
const char *disrobe_bigobj_name(void) { return "disrobe-bigobj"; }
