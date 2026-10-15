void *objc_msgSend(void *self, void *selector) {
    (void)selector;
    return self;
}

void *objc_retain(void *object) {
    return object;
}

void objc_release(void *object) {
    (void)object;
}

void *objc_autorelease(void *object) {
    return object;
}

void *objc_retainAutoreleasedReturnValue(void *object) {
    return object;
}

void *objc_autoreleaseReturnValue(void *object) {
    return object;
}

void *objc_retainAutoreleaseReturnValue(void *object) {
    return object;
}

void objc_storeStrong(void **slot, void *object) {
    *slot = object;
}
