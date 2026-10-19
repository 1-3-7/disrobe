int _fltused = 0;

typedef struct Settings {
    unsigned int magic;
    float exposure;
    float gamma;
    float fog_density;
    double horizon;
    int samples;
    float bloom;
    const char *title;
    const unsigned short *wide_title;
    unsigned long long seed;
} Settings;

int g_counter;
const float k_curve[4] = { 0.15625f, 0.34375f, 0.59375f, 0.90625f };

__declspec(dllexport) void settings_init(Settings *s)
{
    s->magic = 0x5C0FE00Du;
    s->exposure = 1.0625f;
    s->gamma = 2.4375f;
    s->fog_density = 0.0546875f;
    s->horizon = 1234.5625;
    s->samples = 12;
    s->bloom = 0.8125f;
    s->title = "scope-ascii-title";
    s->wide_title = L"scope-wide-title";
    s->seed = 0x9E3779B97F4A7C15ull;
}

__declspec(dllexport) float settings_luma(const Settings *s, float x)
{
    return x * s->exposure * 0.4375f + s->gamma;
}

__declspec(dllexport) double settings_horizon_scale(const Settings *s, double d)
{
    return s->horizon * d * 2.71875;
}

__declspec(noinline) int counter_add(int by)
{
    g_counter += by;
    return g_counter;
}

__declspec(noinline) float curve_at(int i)
{
    return k_curve[i & 3];
}

__declspec(dllexport) int settings_apply(Settings *s, int rounds)
{
    float acc = 0.0f;
    int i;
    for (i = 0; i < rounds; ++i) {
        acc += curve_at(i) * s->bloom;
        counter_add(s->samples);
    }
    s->fog_density = acc;
    return counter_add(1);
}

__declspec(dllexport) float settings_blend(Settings *a, const Settings *b, float t)
{
    float la = settings_luma(a, t);
    float lb = settings_luma(b, 1.0f - t);
    a->bloom = la * 0.5f + lb * 0.5f;
    counter_add(2);
    return a->bloom;
}

__declspec(dllexport) int counter_reset(void)
{
    int old = g_counter;
    g_counter = 0;
    return old;
}

__declspec(dllexport) const char *settings_title(const Settings *s)
{
    return s->title != 0 ? s->title : "scope-default-title";
}
