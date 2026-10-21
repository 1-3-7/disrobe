typedef __SIZE_TYPE__ size_t;
typedef __INTPTR_TYPE__ ssize_t;

long ptrace(int request, int pid, void *addr, void *data);
int open(const char *path, int flags, ...);
ssize_t read(int fd, void *buf, size_t count);
int close(int fd);
char *strstr(const char *haystack, const char *needle);
int inotify_init(void);
int inotify_add_watch(int fd, const char *path, unsigned int mask);
int getppid(void);
int kill(int pid, int sig);
int raise(int sig);
void (*signal(int sig, void (*handler)(int)))(int);
int strcmp(const char *a, const char *b);

static char status_buffer[4096];

int antidebug_ptrace_self(void) {
    return ptrace(0, 0, 0, 0) == -1;
}

int antidebug_tracer_pid(void) {
    int fd = open("/proc/self/status", 0);
    if (fd < 0) {
        return 0;
    }
    ssize_t got = read(fd, status_buffer, sizeof status_buffer - 1);
    close(fd);
    if (got <= 0) {
        return 0;
    }
    status_buffer[got] = 0;
    const char *line = strstr(status_buffer, "TracerPid:");
    return line != 0 && line[10] != '\t' && line[11] != '0';
}

int antidebug_frida_maps(void) {
    int fd = open("/proc/self/maps", 0);
    if (fd < 0) {
        return 0;
    }
    ssize_t got = read(fd, status_buffer, sizeof status_buffer - 1);
    close(fd);
    if (got <= 0) {
        return 0;
    }
    status_buffer[got] = 0;
    return strstr(status_buffer, "frida-agent") != 0 || strstr(status_buffer, "linjector") != 0
        || strstr(status_buffer, "re.frida.server") != 0;
}

int antidebug_frida_thread(const char *thread_name) {
    return strcmp(thread_name, "gum-js-loop") == 0 || strcmp(thread_name, "gmain") == 0;
}

int antidebug_watch_memory(void) {
    int fd = inotify_init();
    if (fd < 0) {
        return 0;
    }
    return inotify_add_watch(fd, "/proc/self/mem", 1) >= 0;
}

int antidebug_parent_is_zygote(void) {
    return kill(getppid(), 0) == 0;
}

static void on_trap(int sig) {
    (void)sig;
}

int antidebug_sigtrap_probe(void) {
    signal(5, on_trap);
    return raise(5) == 0;
}

unsigned char Java_com_planted_audit_Native_antidebugPtraceSelf(void *env, void *clazz) {
    (void)env;
    (void)clazz;
    return (unsigned char)antidebug_ptrace_self();
}

unsigned char Java_com_planted_audit_Native_antidebugTracerPid(void *env, void *clazz) {
    (void)env;
    (void)clazz;
    return (unsigned char)(antidebug_tracer_pid() || antidebug_frida_maps());
}
