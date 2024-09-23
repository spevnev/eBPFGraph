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

static const Color BACKGROUND = {0x18, 0x18, 0x18, 0xff};
static const Color FOREGROUND = {0xD8, 0xD8, 0xD8, 0xff};
static const Color COLORS[] = {{0xD8, 0x18, 0x18, 0xff}, {0x18, 0xD8, 0x18, 0xff}, {0x18, 0x18, 0xD8, 0xff},
                               {0x18, 0xD8, 0xD8, 0xff}, {0xD8, 0x18, 0xD8, 0xff}, {0xD8, 0xD8, 0x18, 0xff}};
#define COLORS_LEN (sizeof(COLORS) / sizeof(*COLORS))

typedef struct {
    uint64_t time_ns;
    int32_t cgroup;
    uint32_t latency_ns;
} Entry;

typedef struct {
    uint64_t time_us;
    uint32_t latency_us;
} Point;

typedef struct {
    int32_t cgroup;
    Color color;

    uint64_t min_time_us;
    uint64_t max_time_us;
    uint32_t min_latency_us;
    uint32_t max_latency_us;

    size_t points_len;
    Point *points;
} Cgroup;

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

    const int LINES = 186134;

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
        long long latency_ns;
        ch = llong_field(&latency_ns, ch);
        assert(0 <= latency_ns && latency_ns <= UINT32_MAX);
        entry->latency_ns = latency_ns;

        // TS
        long long time_ns;
        ch = llong_field(&time_ns, ch);
        assert(0 <= time_ns);
        entry->time_ns = time_ns;

        entry++;
    }
    if (line) free(line);

    *ret_entries = entries;
    *ret_entries_len = entries_len;
    return 0;
}

int process_data(Cgroup **ret_cgroups, size_t *ret_cgroups_len, Entry *entries, size_t entries_len) {
    const int ENTRIES = 20;
    const int POINTS = 180000;

    size_t cgroups_len = ENTRIES;
    Cgroup *cgroups = malloc(cgroups_len * sizeof(*cgroups));
    size_t init_entries = 0;

    for (size_t i = 0; i < cgroups_len; i++) {
        cgroups[i].color = COLORS[i % COLORS_LEN];
        cgroups[i].min_time_us = UINT64_MAX;
        cgroups[i].max_time_us = 0;
        cgroups[i].min_latency_us = UINT32_MAX;
        cgroups[i].max_latency_us = 0;
        cgroups[i].points_len = 0;
        cgroups[i].points = malloc(POINTS * sizeof(*cgroups[i].points));
    }

    for (size_t i = 0; i < entries_len; i++) {
        Cgroup *cgroup = NULL;
        for (size_t j = 0; j < init_entries; j++) {
            if (entries[i].cgroup == cgroups[j].cgroup) {
                cgroup = &cgroups[j];
                break;
            }
        }
        if (cgroup == NULL) {
            assert(init_entries + 1 < cgroups_len);
            cgroup = &cgroups[init_entries++];
            cgroup->cgroup = entries[i].cgroup;
        }

        uint64_t latency_us = entries[i].latency_ns / 1000;
        uint32_t time_us = entries[i].time_ns / 1000;

        if (time_us < cgroup->min_time_us) cgroup->min_time_us = time_us;
        if (time_us > cgroup->max_time_us) cgroup->max_time_us = time_us;
        if (latency_us < cgroup->min_latency_us) cgroup->min_latency_us = latency_us;
        if (latency_us > cgroup->max_latency_us) cgroup->max_latency_us = latency_us;

        // TODO: batch & average
        cgroup->points[cgroup->points_len].latency_us = latency_us;
        cgroup->points[cgroup->points_len].time_us = time_us;
        cgroup->points_len++;
    }

    // TODO: reorder / make it "others"
    const int MIN_POINTS = 1000;
    for (size_t i = 0; i < cgroups_len; i++) {
        if (cgroups[i].points_len < MIN_POINTS) cgroups[i].points_len = 0;
    }
    // TODO: remove/ignore cgroups with less than N points

    *ret_cgroups = cgroups;
    *ret_cgroups_len = cgroups_len;
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

    Cgroup *cgroups;
    size_t cgroups_len;
    if (process_data(&cgroups, &cgroups_len, entries, entries_len) != 0) {
        fprintf(stderr, "ERROR: unable to process data.\n");
        return EXIT_FAILURE;
    }
    free(entries);

    fclose(fp);

    uint64_t min_time_us = UINT64_MAX;
    uint64_t max_time_us = 0;
    uint32_t min_latency_us = UINT32_MAX;
    uint32_t max_latency_us = 0;
    for (size_t i = 0; i < cgroups_len; i++) {
        if (cgroups[i].min_time_us < min_time_us) min_time_us = cgroups[i].min_time_us;
        if (cgroups[i].max_time_us > max_time_us) max_time_us = cgroups[i].max_time_us;
        if (cgroups[i].min_latency_us < min_latency_us) min_latency_us = cgroups[i].min_latency_us;
        if (cgroups[i].max_latency_us > max_latency_us) max_latency_us = cgroups[i].max_latency_us;
    }

    SetTraceLogLevel(LOG_WARNING);
    InitWindow(WIDTH, HEIGHT, TITLE);
    SetTargetFPS(30);

    const float OFFSET_SPEED = 10.0f;

    double offset = 0.0f;
    double x_scale = 1.0f;
    double y_scale = 1.0f;
    bool filter = false;
    size_t filter_idx = 0;
    while (!WindowShouldClose()) {
        if (IsKeyReleased(KEY_Q)) {
            filter = !filter;
        }
        if (IsKeyReleased(KEY_W)) {
            if (filter && filter_idx > 0) filter_idx--;
        }
        if (IsKeyReleased(KEY_E)) {
            if (filter && filter_idx + 1 < cgroups_len) filter_idx++;
        }

        if (IsKeyDown(KEY_LEFT)) {
            offset -= 1.0f / x_scale / OFFSET_SPEED;
            if (offset < 0.0f) offset = 0.0f;
        }
        if (IsKeyDown(KEY_RIGHT)) {
            offset += 1.0f / x_scale / OFFSET_SPEED;
            if (offset > 1.0f) offset = 1.0f;
        }

        if (IsKeyReleased(KEY_UP)) y_scale /= 2;
        if (IsKeyReleased(KEY_DOWN)) y_scale *= 2;

        if (IsKeyReleased(KEY_EQUAL)) x_scale *= 2;
        if (IsKeyReleased(KEY_MINUS)) {
            if (x_scale > 1.0f) x_scale /= 2;
        }

        double ts_per_px = (max_time_us - min_time_us) / INNER_WIDTH;
        double latency_per_px = (max_latency_us * y_scale - min_latency_us) / INNER_HEIGHT;

        BeginDrawing();
        ClearBackground(BACKGROUND);

        for (size_t i = 0; i < cgroups_len; i++) {
            if (filter && i != filter_idx) continue;

            Cgroup entry = cgroups[i];

            int px = H_PADDING;
            int py = HEIGHT - V_PADDING;

            for (size_t j = 0; j < entry.points_len; j++) {
                Point point = entry.points[j];

                int x = H_PADDING + (round((point.time_us - min_time_us) / ts_per_px) - INNER_WIDTH * offset) * x_scale;
                if (x > WIDTH - H_PADDING) break;
                int y = HEIGHT - V_PADDING - round((point.latency_us - min_latency_us) / (latency_per_px * y_scale));
                if (y < V_PADDING) y = V_PADDING;

                DrawLine(px, py, x, y, entry.color);

                px = x;
                py = y;
            }
        }

        EndDrawing();
    }

    CloseWindow();

    for (size_t i = 0; i < cgroups_len; i++) free(cgroups[i].points);
    free(cgroups);

    return EXIT_SUCCESS;
}
