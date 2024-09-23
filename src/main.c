#define _DEFAULT_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <raylib.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// TODO: full screen?
static const int WIDTH = 1080;
static const int HEIGHT = 720;
static const char *TITLE = "eBPF Graph";

static const Color BACKGROUND = {0x18, 0x18, 0x18, 0xff};

static void usage(const char *program) {
    printf("usage: %s <filename>\n", program);
}

int main(int argc, char *argv[]) {
    if (RAYLIB_VERSION_MAJOR != 5) {
        fprintf(stderr, "ERROR: required raylib version is 5.y.z.\n");
        return EXIT_FAILURE;
    }

    assert(argc > 0);
    const char *program = argv[0];

    if (argc != 2) {
        usage(program);
        return EXIT_FAILURE;
    }

    FILE *fp = fopen(argv[1], "r");
    if (fp == NULL) {
        fprintf(stderr, "ERROR: unable to open file \"%s\": %s.\n", argv[1], strerror(errno));
        usage(program);
        return EXIT_FAILURE;
    }

    fclose(fp);

    SetTraceLogLevel(LOG_WARNING);
    InitWindow(WIDTH, HEIGHT, TITLE);
    SetTargetFPS(30);

    while (!WindowShouldClose()) {
        BeginDrawing();

        ClearBackground(BACKGROUND);

        EndDrawing();
    }

    CloseWindow();
    return EXIT_SUCCESS;
}
