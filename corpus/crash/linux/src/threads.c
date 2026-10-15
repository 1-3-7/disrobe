#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

static volatile int ready;

static void *idle_worker(void *argument) {
    (void)argument;
    for (;;) {
        ready += 1;
        sleep(1);
    }
    return NULL;
}

static void *crashing_worker(void *argument) {
    volatile int *pointer = (volatile int *)argument;
    sleep(1);
    *pointer = 1;
    return NULL;
}

int main(void) {
    pthread_t first;
    pthread_t second;
    pthread_t third;
    pthread_create(&first, NULL, idle_worker, NULL);
    pthread_create(&second, NULL, idle_worker, NULL);
    pthread_create(&third, NULL, crashing_worker, (void *)16);
    pthread_join(third, NULL);
    return 0;
}
