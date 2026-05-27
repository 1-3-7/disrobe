int answer(void) {
    return 42;
}

int main(int argc, char **argv) {
    (void)argv;
    return answer() + argc;
}
