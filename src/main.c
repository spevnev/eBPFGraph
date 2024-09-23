#define _DEFAULT_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
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

static const int H_PADDING = 50;
static const int V_PADDING = 25;

#define INNER_WIDTH (WIDTH - 2 * H_PADDING)
#define INNER_HEIGHT (HEIGHT - 2 * V_PADDING)

static const char *TITLE = "eBPF Graph";

static const Color BACKGROUND = {0x18, 0x18, 0x18, 0xff};

typedef struct {
    uint64_t ts;
    int32_t cgroup;
    uint32_t latency;
} Entry;

static void usage(const char *program) {
    printf("usage: %s <filename>\n", program);
}

static const char *skip_field(const char *ch) {
    while (*ch == ' ' && *ch != '\0') ch++;
    while (*ch != ' ' && *ch != '\0') ch++;
    assert(*ch != '\0');
    return ch;
}

static const char *llong_field(long long *ret, const char *ch) {
    while (*ch == ' ') ch++;

    char *end = NULL;
    *ret = strtoll(ch, &end, 10);
    assert(end != NULL && ch < end);

    return end;
}

static int parse_output(Entry **ret_entries, size_t *ret_entries_len, FILE *fp) {
    assert(ret_entries != NULL && ret_entries_len != NULL && fp != NULL);  // TODO: error vs assert

    const int LINES = 186135;

    size_t entries_len = LINES;
    Entry *entries = malloc(entries_len * sizeof(*entries));  // TODO: just mmap?
    Entry *entry = entries;

    bool skipped_header = false;
    ssize_t read;
    char *line;
    size_t line_len;
    while ((read = getline(&line, &line_len, fp)) != -1) {
        if (!skipped_header) {
            skipped_header = true;
            continue;
        }

        const char *ch = line;

        // TIME
        ch = skip_field(ch);

        // PREV_CGROUP
        ch = skip_field(ch);

        // CGROUP
        long long cgroup;
        ch = llong_field(&cgroup, ch);
        assert(0 <= cgroup && cgroup <= INT32_MAX);
        entry->cgroup = cgroup;

        // RUNQ_LATENCY
        long long latency;
        ch = llong_field(&latency, ch);
        assert(0 <= latency && latency <= UINT32_MAX);
        entry->latency = latency;

        // TS
        long long ts;
        ch = llong_field(&ts, ch);
        assert(0 <= ts);
        entry->ts = ts;

        entry++;
    }
    if (line) free(line);

    *ret_entries = entries;
    *ret_entries_len = entries_len;
    return 0;
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

    Entry *entries;
    size_t entries_len;
    if (parse_output(&entries, &entries_len, fp) != 0) {
        fprintf(stderr, "ERROR: unable to parse file.\n");
        return EXIT_FAILURE;
    }

    fclose(fp);

    uint64_t min_ts = entries[0].ts;
    uint64_t max_ts = entries[entries_len - 1].ts;
    double ts_per_px = (max_ts - min_ts) / INNER_WIDTH;

    uint64_t min_latency = UINT64_MAX;
    uint64_t max_latency = 0;
    for (size_t i = 0; i < entries_len; i++) {
        Entry entry = entries[i];
        if (entry.latency < min_latency) min_latency = entry.latency;
        if (entry.latency > max_latency) max_latency = entry.latency;
    }
    double latency_per_px = (max_latency - min_latency) / INNER_HEIGHT;

    SetTraceLogLevel(LOG_WARNING);
    InitWindow(WIDTH, HEIGHT, TITLE);
    SetTargetFPS(30);

    while (!WindowShouldClose()) {
        BeginDrawing();

        ClearBackground(BACKGROUND);

        int px = H_PADDING;
        int py = V_PADDING;
        for (size_t i = 0; i < entries_len; i++) {
            Entry entry = entries[i];
            int x = H_PADDING + round((entry.ts - min_ts) / ts_per_px);
            int y = V_PADDING + INNER_HEIGHT - round((entry.latency - min_latency) / latency_per_px);

            DrawLine(px, py, x, y, RAYWHITE);

            px = x;
            py = y;
        }

        EndDrawing();
    }

    CloseWindow();

    free(entries);

    return EXIT_SUCCESS;
}
