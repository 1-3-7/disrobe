typedef struct { const char* name; const char* signature; void* fnPtr; } JNINativeMethod;

__attribute__((visibility("default"))) int nativeAdd(void* env, void* thiz, int a, int b) { return a + b; }
__attribute__((visibility("default"))) long nativeLen(void* env, void* thiz, void* s) { return (long)s; }
__attribute__((visibility("default"))) void nativeNoop(void* env, void* thiz) { (void)env; (void)thiz; }
static int hiddenMul(void* env, void* thiz, int a, int b) { return a * b; }

static const JNINativeMethod methods[] = {
    { "nativeAdd",  "(II)I",                 (void*)nativeAdd  },
    { "nativeLen",  "(Ljava/lang/String;)J", (void*)nativeLen  },
    { "nativeNoop", "()V",                    (void*)nativeNoop },
    { "hiddenMul",  "(II)I",                 (void*)hiddenMul  },
};

volatile const void* keep_methods;
int JNI_OnLoad(void* vm, void* reserved) {
    (void)vm; (void)reserved;
    keep_methods = (const void*)&methods[0];
    return 0x00010006;
}
