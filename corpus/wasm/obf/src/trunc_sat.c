int i32_from_f32_s(float a) { return (int)a; }
unsigned i32_from_f32_u(float a) { return (unsigned)a; }
int i32_from_f64_s(double a) { return (int)a; }
unsigned i32_from_f64_u(double a) { return (unsigned)a; }
long long i64_from_f32_s(float a) { return (long long)a; }
unsigned long long i64_from_f32_u(float a) { return (unsigned long long)a; }
long long i64_from_f64_s(double a) { return (long long)a; }
unsigned long long i64_from_f64_u(double a) { return (unsigned long long)a; }
int mixed(double a, float b) { return (int)a + (int)(unsigned)b; }
