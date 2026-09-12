typedef unsigned long ulong_t;
typedef long long_t;

#define NOINLINE __attribute__((noinline))
#define USED __attribute__((used))

NOINLINE static long_t widen_lo(long_t v) { return (v << 3) - 7; }

NOINLINE static long_t widen_hi(long_t v) { return (v >> 2) + 11; }

NOINLINE static long_t blend_pair(long_t a, long_t b) {
  return widen_lo(a) ^ widen_hi(b);
}

NOINLINE static long_t clamp_low(long_t v) { return v < 0 ? 0 : v; }

NOINLINE static long_t clamp_high(long_t v) { return v > 4096 ? 4096 : v; }

NOINLINE static long_t saturate(long_t v) { return clamp_high(clamp_low(v)); }

NOINLINE static long_t table_zero(long_t v) { return v + 101; }

NOINLINE static long_t table_one(long_t v) { return v * 3 + 5; }

NOINLINE static long_t table_two(long_t v) { return (v ^ 0x5a5a) - 17; }

NOINLINE static long_t table_three(long_t v) { return saturate(v) + 23; }

NOINLINE static long_t table_four(long_t v) { return blend_pair(v, v + 9); }

NOINLINE static long_t table_five(long_t v) {
  long_t acc = 0;
  for (long_t i = 0; i < 8; ++i) {
    acc += (v + i) & 0x3f;
  }
  return acc;
}

NOINLINE static long_t table_six(long_t v) {
  switch ((int)(v & 7)) {
    case 0:
      return v + 1;
    case 1:
      return v - 1;
    case 2:
      return v * 2;
    case 3:
      return v / 3;
    case 4:
      return v % 5;
    case 5:
      return v << 2;
    case 6:
      return v >> 1;
    default:
      return ~v;
  }
}

NOINLINE static long_t table_seven(long_t v) { return -v - 3; }

typedef long_t (*unary_fn)(long_t);

USED static unary_fn const dispatch[8] = {
    table_zero, table_one,  table_two,  table_three,
    table_four, table_five, table_six,  table_seven,
};

NOINLINE static long_t deep_helper_a(long_t v) { return v ^ 0x1234; }

NOINLINE static long_t deep_helper_b(long_t v) { return deep_helper_a(v) + 7; }

NOINLINE static long_t deep_helper_c(long_t v) { return deep_helper_b(v) * 5; }

NOINLINE static long_t unwind_shape(long_t v) {
  long_t acc = deep_helper_c(v);
  for (long_t i = 1; i < 5; ++i) {
    acc = blend_pair(acc, i);
  }
  return acc;
}

USED static unary_fn const late_bound[2] = {deep_helper_c, unwind_shape};

NOINLINE static long_t only_from_data(long_t v) { return v * 31 + 4; }

NOINLINE static long_t also_only_from_data(long_t v) { return v * 17 - 4; }

USED static unary_fn const hidden_pair[2] = {only_from_data, also_only_from_data};

static long_t ctor_state;

USED static void discovery_ctor(void) { ctor_state = 0x2468; }

USED static void discovery_dtor(void) { ctor_state = 0; }

__attribute__((section(".init_array"), used)) static void (*ctor_slot)(void) =
    discovery_ctor;

__attribute__((section(".fini_array"), used)) static void (*dtor_slot)(void) =
    discovery_dtor;

NOINLINE long_t exported_entry(long_t v) {
  long_t acc = ctor_state;
  for (int i = 0; i < 8; ++i) {
    acc += dispatch[i](v + i);
  }
  acc += late_bound[v & 1](acc);
  acc += hidden_pair[(v >> 1) & 1](acc);
  return acc;
}

NOINLINE long_t exported_second(long_t v) { return saturate(v) + unwind_shape(v); }

NOINLINE long_t exported_third(long_t v) { return table_six(v) ^ deep_helper_b(v); }
