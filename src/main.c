#define _DEFAULT_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/prctl.h>
#include <math.h>
#include <raylib.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

// Window
static const char *TITLE = "eBPF Graph";
static const int WIDTH = 1600;
static const int HEIGHT = 900;

// UI sizes
static const int HOR_PADDING = 60;
static const int TOP_PADDING = 60;
static const int BOT_PADDING = 40;
#define INNER_WIDTH (WIDTH - 2 * HOR_PADDING)
#define INNER_HEIGHT (HEIGHT - TOP_PADDING - BOT_PADDING)
static const int GRID_SIZE = 60;
static const int AXIS_FONT_SIZE = 10;
static const int TEXT_MARGIN = 4;
static const int LEGEND_COLOR_SIZE = 16;
static const int LEGEND_COLOR_PADDING = 4;
static const int LEGEND_COLOR_THICKNESS = 2;
static const int LEGEND_FONT_SIZE = 16;
static const int LEGEND_PADDING = 20;

// Colors
static const Color BACKGROUND = {0x18, 0x18, 0x18, 0xff};
static const Color FOREGROUND = {0xD8, 0xD8, 0xD8, 0xff};
static const Color GRID_COLOR = {0x33, 0x33, 0x33, 0xff};
static const Color COLORS[] = {{0xD8, 0x18, 0x18, 0xff}, {0x18, 0xD8, 0x18, 0xff}, {0x18, 0x18, 0xD8, 0xff},
                               {0x18, 0xD8, 0xD8, 0xff}, {0xD8, 0x18, 0xD8, 0xff}, {0xD8, 0xD8, 0x18, 0xff}};
#define COLORS_LEN (sizeof(COLORS) / sizeof(*COLORS))

// Grouping
static const size_t CGROUP_MIN_POINTS = 500;

// Controls
static const float OFFSET_SPEED = 20.0f;
static const float X_SCALE_SPEED = 1.05f;
static const float Y_SCALE_SPEED = 1.05f;
static const float MIN_Y_SCALE = 0.8f;

// Memory
static const size_t DEFAULT_ENTRIES_CAPACITY = 65536;
static const size_t DEFAULT_CGROUPS_CAPACITY = 64;
static const size_t DEFAULT_POINTS_CAPACITY = 16384;

typedef struct {
    int time_s;
    uint64_t ts_ns;
    int32_t cgroup;
    uint32_t latency_ns;
} Entry;

typedef struct {
    uint64_t ts_us;
    uint32_t latency_us;
} Point;

typedef struct {
    int32_t cgroup;
    Color color;

    uint64_t min_ts_us;
    uint64_t max_ts_us;
    uint32_t min_latency_us;
    uint32_t max_latency_us;

    size_t points_capacity;
    size_t points_len;
    Point *points;
} Cgroup;

#define MeasureText2(text, font_size) \
    MeasureTextEx(GetFontDefault(), (text), (font_size), (font_size) / GetFontDefault().baseSize)

#define MAX(a, b) ((a) >= (b) ? (a) : (b))
#define MIN(a, b) ((a) <= (b) ? (a) : (b))

static const char *skip_field(const char *ch) {
    assert(ch != NULL);

    while (*ch == ' ') ch++;
    while (*ch != ' ' && *ch != '\0') ch++;

    return ch;
}

static const char *time_field(int *ret_s, const char *ch) {
    assert(ret_s != NULL && ch != NULL);

    while (*ch == ' ') ch++;

    char *end = NULL;

    long h = strtol(ch, &end, 10);
    assert(ch < end);
    ch = end + 1;

    long m = strtol(ch, &end, 10);
    assert(ch < end);
    ch = end + 1;

    long s = strtol(ch, &end, 10);
    assert(ch < end);

    *ret_s = h * 3600 + m * 60 + s;
    return end;
}

static const char *llong_field(long long *ret, const char *ch) {
    assert(ret != NULL && ch != NULL);

    while (*ch == ' ') ch++;

    char *end = NULL;
    *ret = strtoll(ch, &end, 10);
    assert(ch < end);

    return end;
}

static void parse_output(Entry **ret_entries, size_t *ret_entries_len, FILE *fp) {
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
        int time_s;
        ch = time_field(&time_s, ch);
        assert(0 <= time_s);
        entries[entries_len].time_s = time_s;

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
        long long ts_ns;
        ch = llong_field(&ts_ns, ch);
        assert(0 <= ts_ns);
        entries[entries_len].ts_ns = ts_ns;

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
}

static void process_data(Cgroup **ret_cgroups, size_t *ret_cgroups_len, Entry *entries, size_t entries_len) {
    assert(ret_cgroups != NULL && ret_cgroups_len != NULL && entries != NULL);

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
            cgroup->min_ts_us = UINT64_MAX;
            cgroup->max_ts_us = 0;
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
        uint32_t ts_us = entries[i].ts_ns / 1000;

        cgroup->min_ts_us = MIN(cgroup->min_ts_us, ts_us);
        cgroup->max_ts_us = MAX(cgroup->max_ts_us, ts_us);
        cgroup->min_latency_us = MIN(cgroup->min_latency_us, latency_us);
        cgroup->max_latency_us = MAX(cgroup->max_latency_us, latency_us);

        // TODO: batch & average

        cgroup->points[cgroup->points_len].latency_us = latency_us;
        cgroup->points[cgroup->points_len].ts_us = ts_us;
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

    for (size_t i = l; i < cgroups_len; i++) free(cgroups[i].points);
    cgroups_len = l;

    *ret_cgroups = cgroups;
    *ret_cgroups_len = cgroups_len;
}

static bool button(Rectangle rec) {
    bool is_mouse_over = CheckCollisionPointRec(GetMousePosition(), rec);
    if (!is_mouse_over) return false;

    SetMouseCursor(MOUSE_CURSOR_POINTING_HAND);
    return IsMouseButtonPressed(MOUSE_BUTTON_LEFT);
}

static int start_ebpf(pid_t *child) {
    int fd[2];
    if (pipe(fd) == -1) abort();  // TODO:
    int read_fd = fd[0];
    int write_fd = fd[1];

    prctl(PR_SET_PDEATHSIG, SIGTERM);

    pid_t pid = fork();
    if (pid == -1) abort();  // TODO:

    // TODO: error handling:
    if (pid == 0) {
        dup2(write_fd, STDOUT_FILENO);
        close(read_fd);
        // TODO: remove absolute path
        execle("/home/tx/srcs/eunomia/ecli", "ecli", "run", "ebpf/package.json");
        exit(EXIT_FAILURE);
    }

    close(write_fd);

    *child = pid;
    return read_fd;
}

int main(int argc, char *argv[]) {
    if (RAYLIB_VERSION_MAJOR != 5) {
        fprintf(stderr, "ERROR: the required raylib version is 5.\n");
        return EXIT_FAILURE;
    }

    assert(argc > 0);
    const char *program = argv[0];

    if (argc != 2) {
        printf("usage: %s <filename>\n", program);
        return EXIT_FAILURE;
    }

    if (geteuid() != 0) {
        fprintf(stderr, "ERROR: must be ran as root.\n");
        return EXIT_FAILURE;
    }

    pid_t child;
    int input_fd = start_ebpf(&child);
    getchar();
    kill(child, SIGTERM);
    close(input_fd);

    if (setgid(1000) != 0 || setuid(1000) != 0) {
        fprintf(stderr, "ERROR: unable to drop user privileges.\n");
        return EXIT_FAILURE;
    }

    return 0;

    FILE *fp = fopen(argv[1], "r");
    if (fp == NULL) {
        fprintf(stderr, "ERROR: unable to open file \"%s\": %s.\n", argv[1], strerror(errno));
        return EXIT_FAILURE;
    }

    Entry *entries;
    size_t entries_len;
    parse_output(&entries, &entries_len, fp);

    int min_time_s = entries[0].time_s;
    int max_time_s = entries[entries_len - 1].time_s;
    double time_per_px = (max_time_s - min_time_s) / ((double) INNER_WIDTH);

    Cgroup *cgroups;
    size_t cgroups_len;
    process_data(&cgroups, &cgroups_len, entries, entries_len);

    free(entries);
    fclose(fp);

    uint64_t min_ts_us = UINT64_MAX;
    uint64_t max_ts_us = 0;
    uint32_t min_latency_us = UINT32_MAX;
    uint32_t max_latency_us = 0;
    for (size_t i = 0; i < cgroups_len; i++) {
        min_ts_us = MIN(min_ts_us, cgroups[i].min_ts_us);
        max_ts_us = MAX(max_ts_us, cgroups[i].max_ts_us);
        min_latency_us = MIN(min_latency_us, cgroups[i].min_latency_us);
        max_latency_us = MAX(max_latency_us, cgroups[i].max_latency_us);
    }

    double ts_per_px = (max_ts_us - min_ts_us) / ((double) INNER_WIDTH);
    double latency_per_px = (max_latency_us - min_latency_us) / ((double) INNER_HEIGHT);

    double offset = 0.0f;
    double x_scale = 1.0f;
    double y_scale = 1.0f;

    bool *enabled_cgroups = malloc(cgroups_len * sizeof(*enabled_cgroups));
    assert(enabled_cgroups != NULL);
    memset(enabled_cgroups, true, cgroups_len);

    SetTraceLogLevel(LOG_WARNING);
    InitWindow(WIDTH, HEIGHT, TITLE);
    SetTargetFPS(30);

    while (!WindowShouldClose()) {
        if (IsKeyDown(KEY_LEFT)) offset = MAX(offset - 1.0f / (x_scale * OFFSET_SPEED), 0.0f);
        if (IsKeyDown(KEY_RIGHT)) offset = MIN(offset + 1.0f / (OFFSET_SPEED * x_scale), 1.0f - 1.0f / x_scale);

        if (IsKeyDown(KEY_EQUAL)) x_scale *= X_SCALE_SPEED;
        if (IsKeyDown(KEY_MINUS)) {
            x_scale = MAX(x_scale / X_SCALE_SPEED, 1.0f);
            offset = MIN(offset, 1.0f - 1.0f / x_scale);
        }

        if (IsKeyDown(KEY_UP)) y_scale *= Y_SCALE_SPEED;
        if (IsKeyDown(KEY_DOWN)) y_scale = MAX(y_scale / Y_SCALE_SPEED, MIN_Y_SCALE);

        BeginDrawing();
        ClearBackground(BACKGROUND);
        SetMouseCursor(MOUSE_CURSOR_DEFAULT);

        char buffer[256];
        for (int i = 0; i <= INNER_WIDTH / GRID_SIZE; i++) {
            int x = i * GRID_SIZE + HOR_PADDING;
            DrawLine(x, TOP_PADDING, x, HEIGHT - BOT_PADDING, GRID_COLOR);

            uint64_t ts_us = min_ts_us + ts_per_px * i * GRID_SIZE / x_scale + (max_ts_us - min_ts_us) * offset;
            snprintf(buffer, 256, "%llu", (long long unsigned int) ts_us);
            Vector2 td = MeasureText2(buffer, AXIS_FONT_SIZE);
            DrawText(buffer, x - td.x / 2, HEIGHT - BOT_PADDING + TEXT_MARGIN, AXIS_FONT_SIZE, FOREGROUND);

            int time_s = min_time_s + time_per_px * i * GRID_SIZE / x_scale + (max_time_s - min_time_s) * offset;
            snprintf(buffer, 256, "%d:%02d:%02d", (time_s / 3600) % 24, (time_s / 60) % 60, time_s % 60);
            int tw = MeasureText(buffer, AXIS_FONT_SIZE);
            DrawText(buffer, x - tw / 2, HEIGHT - BOT_PADDING + TEXT_MARGIN + td.y + TEXT_MARGIN, AXIS_FONT_SIZE,
                     FOREGROUND);
        }
        for (int i = 0; i <= INNER_HEIGHT / GRID_SIZE; i++) {
            int y = HEIGHT - BOT_PADDING - GRID_SIZE * i;
            DrawLine(HOR_PADDING, y, WIDTH - HOR_PADDING, y, GRID_COLOR);

            uint32_t latency_us = min_latency_us + latency_per_px * i * GRID_SIZE / y_scale;
            snprintf(buffer, 256, "%u", (unsigned int) latency_us);
            Vector2 td = MeasureText2(buffer, AXIS_FONT_SIZE);
            DrawText(buffer, HOR_PADDING - td.x - TEXT_MARGIN, y - td.y / 2, AXIS_FONT_SIZE, FOREGROUND);
        }

        int w = HOR_PADDING;
        for (size_t i = 0; i < cgroups_len; i++) {
            Rectangle rec = {
                .x = w,
                .y = (TOP_PADDING - LEGEND_COLOR_SIZE) / 2,
                .width = LEGEND_COLOR_SIZE,
                .height = LEGEND_FONT_SIZE,
            };

            if (enabled_cgroups[i]) {
                DrawRectangleRec(rec, cgroups[i].color);
            } else {
                DrawRectangleLinesEx(rec, LEGEND_COLOR_THICKNESS, cgroups[i].color);
            }
            w += LEGEND_COLOR_SIZE + LEGEND_COLOR_PADDING;

            bool is_clicked = button(rec);
            if (is_clicked) enabled_cgroups[i] = !enabled_cgroups[i];

            snprintf(buffer, 256, "%d", cgroups[i].cgroup);
            Vector2 td = MeasureText2(buffer, LEGEND_FONT_SIZE);
            DrawText(buffer, w, (TOP_PADDING - td.y) / 2, LEGEND_FONT_SIZE, cgroups[i].color);
            w += td.x + LEGEND_PADDING;
        }

        for (size_t i = 0; i < cgroups_len; i++) {
            if (!enabled_cgroups[i]) continue;
            Cgroup entry = cgroups[i];

            int px = -1;
            int py = -1;
            int npx, npy;
            for (size_t j = 0; j < entry.points_len; j++, px = npx, py = npy) {
                Point point = entry.points[j];

                int x = (point.ts_us - min_ts_us - (max_ts_us - min_ts_us) * offset) / ts_per_px * x_scale;
                int y = round((point.latency_us - min_latency_us) / latency_per_px) * y_scale;

                npx = x;
                npy = y;

                if (x < 0) continue;
                if (y > INNER_HEIGHT && py > INNER_HEIGHT) continue;
                if (px == -1) continue;

                int rpx = px;
                int rpy = py;
                int rx = x;
                int ry = y;

                if (rpx < 0) {
                    assert(x != px);
                    double k = px / ((double) (px - x));
                    rpx = 0;
                    rpy = py + (y - py) * k;
                }
                if (rx > INNER_WIDTH) {
                    assert(x != px);
                    double k = (x - INNER_WIDTH) / ((double) (x - px));
                    rx = INNER_WIDTH;
                    ry = py + (y - py) * (1.0f - k);
                }
                if (rpy > INNER_HEIGHT) {
                    assert(y != py);
                    double k = (py - INNER_HEIGHT) / ((double) (py - y));
                    rpx = px + (x - px) * k;
                    rpy = INNER_HEIGHT;
                }
                if (ry > INNER_HEIGHT) {
                    assert(y != py);
                    double k = (y - INNER_HEIGHT) / ((double) (y - py));
                    rx = px + (x - px) * (1.0f - k);
                    ry = INNER_HEIGHT;
                }

                DrawLine(HOR_PADDING + rpx, HEIGHT - BOT_PADDING - rpy, HOR_PADDING + rx, HEIGHT - BOT_PADDING - ry,
                         entry.color);

                if (x >= INNER_WIDTH) break;
            }
        }

        EndDrawing();
    }

    CloseWindow();

    free(enabled_cgroups);
    for (size_t i = 0; i < cgroups_len; i++) free(cgroups[i].points);
    free(cgroups);

    return EXIT_SUCCESS;
}
