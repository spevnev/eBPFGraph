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

static const char *TITLE = "eBPF Graph";

// Geometry
static const int WIDTH = 1080;
static const int HEIGHT = 720;
static const int H_PADDING = 50;
static const int V_PADDING = 25;
#define INNER_WIDTH (WIDTH - 2 * H_PADDING)
#define INNER_HEIGHT (HEIGHT - 2 * V_PADDING)

// Colors
static const Color BACKGROUND = {0x18, 0x18, 0x18, 0xff};
static const Color FOREGROUND = {0xD8, 0xD8, 0xD8, 0xff};
static const Color COLORS[] = {{0xD8, 0x18, 0x18, 0xff}, {0x18, 0xD8, 0x18, 0xff}, {0x18, 0x18, 0xD8, 0xff},
                               {0x18, 0xD8, 0xD8, 0xff}, {0xD8, 0x18, 0xD8, 0xff}, {0xD8, 0xD8, 0x18, 0xff}};
#define COLORS_LEN (sizeof(COLORS) / sizeof(*COLORS))

// Grouping
static const size_t CGROUP_MIN_POINTS = 500;

// Controls
static const float OFFSET_SPEED = 10.0f;
static const float MIN_Y_SCALE = 0.01f;
static const float Y_SCALE_SPEED = 1.08f;
static const float X_SCALE_SPEED = 1.05f;

// Memory
static const size_t DEFAULT_ENTRIES_CAPACITY = 65536;
static const size_t DEFAULT_CGROUPS_CAPACITY = 64;
static const size_t DEFAULT_POINTS_CAPACITY = 16384;

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

    size_t points_capacity;
    size_t points_len;
    Point *points;
} Cgroup;

static void usage(const char *program) {
    assert(program != NULL);
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
    assert(ret_entries != NULL && ret_entries_len != NULL && fp != NULL);

    size_t entries_capacity = DEFAULT_ENTRIES_CAPACITY;
    size_t entries_len = 0;
    Entry *entries = malloc(entries_capacity * sizeof(*entries));
    assert(entries != NULL);

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
        entries[entries_len].cgroup = cgroup;

        // RUNQ_LATENCY
        long long latency_ns;
        ch = llong_field(&latency_ns, ch);
        assert(0 <= latency_ns && latency_ns <= UINT32_MAX);
        entries[entries_len].latency_ns = latency_ns;

        // TS
        long long time_ns;
        ch = llong_field(&time_ns, ch);
        assert(0 <= time_ns);
        entries[entries_len].time_ns = time_ns;

        entries_len++;
        if (entries_len == entries_capacity) {
            entries_capacity *= 2;
            entries = realloc(entries, entries_capacity * sizeof(*entries));
            assert(entries != NULL);
        }
    }
    if (line) free(line);

    *ret_entries = entries;
    *ret_entries_len = entries_len;
    return 0;
}

int process_data(Cgroup **ret_cgroups, size_t *ret_cgroups_len, Entry *entries, size_t entries_len) {
    size_t cgroups_capacity = DEFAULT_CGROUPS_CAPACITY;
    size_t cgroups_len = 0;
    Cgroup *cgroups = malloc(cgroups_capacity * sizeof(*cgroups));
    assert(cgroups != NULL);

    for (size_t i = 0; i < entries_len; i++) {
        Cgroup *cgroup = NULL;
        for (size_t j = 0; j < cgroups_len; j++) {
            if (entries[i].cgroup == cgroups[j].cgroup) {
                cgroup = &cgroups[j];
                break;
            }
        }

        if (cgroup == NULL) {
            cgroup = &cgroups[cgroups_len];
            cgroup->cgroup = entries[i].cgroup;
            cgroup->color = COLORS[cgroups_len % COLORS_LEN];
            cgroup->min_time_us = UINT64_MAX;
            cgroup->max_time_us = 0;
            cgroup->min_latency_us = UINT32_MAX;
            cgroup->max_latency_us = 0;
            cgroup->points_capacity = DEFAULT_POINTS_CAPACITY;
            cgroup->points_len = 0;
            cgroup->points = malloc(cgroup->points_capacity * sizeof(*cgroups[i].points));
            assert(cgroup->points != NULL);
            cgroups_len++;

            if (cgroups_len == cgroups_capacity) {
                cgroups_capacity *= 2;
                cgroups = realloc(cgroups, cgroups_capacity * sizeof(*cgroups));
                assert(cgroups != NULL);
            }
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

        if (cgroup->points_len == cgroup->points_capacity) {
            cgroup->points_capacity *= 2;
            cgroup->points = realloc(cgroup->points, cgroup->points_capacity * sizeof(*cgroup->points));
            assert(cgroup->points != NULL);
        }
    }

    size_t l = 0, r = cgroups_len - 1;
    while (l < r) {
        while (l < r && cgroups[l].points_len >= CGROUP_MIN_POINTS) l++;
        while (l < r && cgroups[r].points_len < CGROUP_MIN_POINTS) r--;
        if (l < r) {
            Cgroup temp = cgroups[l];
            cgroups[l] = cgroups[r];
            cgroups[r] = temp;
            l++;
            r--;
        }
    }

    for (size_t i = l; i < cgroups_len; i++) free(cgroups[i].points);
    cgroups_len = l;

    // TODO: group into "others" line; requires merging points
    //     l++;
    //     Cgroup *other = &cgroups[l];
    //     size_t others_len = 0;
    //     for (size_t i = l; i < cgroups_len; i++) others_len += cgroups[i].points_len;
    //     if (other->points_capacity < others_len) {
    //         other->points = realloc(other->points, others_len * sizeof(*other->points));
    //         assert(other->points != NULL);
    //     }
    //
    //     other->cgroup = -1;
    //     for (size_t i = l + 1; i < cgroups_len; i++) {
    //         memcpy(other->points + other->points_len, cgroups[i].points,
    //                cgroups[i].points_len * sizeof(*cgroups[i].points));
    //         other->points_len += cgroups[i].points_len;
    //     }

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

    double ts_per_px = (max_time_us - min_time_us) / INNER_WIDTH;
    double latency_per_px = (max_latency_us - min_latency_us) / INNER_HEIGHT;

    SetTraceLogLevel(LOG_WARNING);
    InitWindow(WIDTH, HEIGHT, TITLE);
    SetTargetFPS(30);

    double offset = 0.0f;
    double x_scale = 1.0f;
    double y_scale = 1.0f;
    bool filter = false;
    size_t filter_idx = 0;
    while (!WindowShouldClose()) {
        // TODO: min & max to simplify:

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

        // TODO: double vs float
        if (IsKeyDown(KEY_UP)) {
            y_scale *= Y_SCALE_SPEED;
        }
        if (IsKeyDown(KEY_DOWN)) {
            y_scale /= Y_SCALE_SPEED;
            if (y_scale < 0.8f) y_scale = 0.8f;
        }

        if (IsKeyDown(KEY_EQUAL)) {
            x_scale *= X_SCALE_SPEED;
        }
        if (IsKeyDown(KEY_MINUS)) {
            x_scale /= X_SCALE_SPEED;
            if (x_scale < 1.0f) x_scale = 1.0f;
        }

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
                int y = HEIGHT - V_PADDING - round((point.latency_us - min_latency_us) / latency_per_px) * y_scale;
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
