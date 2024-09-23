#include <raylib.h>
#include <stdio.h>
#include <stdlib.h>

// TODO: full screen?
static const int WIDTH = 1080;
static const int HEIGHT = 720;
static const char *TITLE = "eBPF Graph";

int main(void) {
    if (RAYLIB_VERSION_MAJOR != 5) {
        fprintf(stderr, "ERROR: required raylib version is 5.y.z.\n");
        return EXIT_FAILURE;
    }

    SetTraceLogLevel(LOG_WARNING);
    InitWindow(WIDTH, HEIGHT, TITLE);
    SetTargetFPS(30);

    while (!WindowShouldClose()) {
        BeginDrawing();

        ClearBackground(RAYWHITE);
        DrawText("Congrats! You created your first window!", 190, 200, 20, LIGHTGRAY);

        EndDrawing();
    }

    CloseWindow();
    return EXIT_SUCCESS;
}
