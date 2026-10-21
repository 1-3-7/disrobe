typedef __SIZE_TYPE__ size_t;

char *strstr(const char *haystack, const char *needle);
size_t strlen(const char *text);

static const char *const greeting = "audit native control";

int clean_add(int left, int right) {
    return left + right;
}

size_t clean_greeting_length(void) {
    return strlen(greeting);
}

int clean_has_word(const char *text) {
    return strstr(text, "control") != 0;
}

int Java_com_planted_audit_Native_cleanAdd(void *env, void *clazz, int left, int right) {
    (void)env;
    (void)clazz;
    return clean_add(left, right);
}
