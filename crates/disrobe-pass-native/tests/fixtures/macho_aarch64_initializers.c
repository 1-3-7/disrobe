static volatile int state;

static void initialize_probe(void) {
    state = 17;
}

static void terminate_probe(void) {
    state = 29;
}

__attribute__((used, section("__DATA,__mod_init_func,mod_init_funcs")))
static void (*const initialize_slot)(void) = initialize_probe;

__attribute__((used, section("__DATA,__mod_term_func,mod_term_funcs")))
static void (*const terminate_slot)(void) = terminate_probe;

int main(void) {
    return state;
}
