#define _DEFAULT_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/prctl.h>
#include <math.h>
#include <raylib.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/wait.h>
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
static const size_t CGROUP_MIN_POINTS = 500;  // TODO: percentage from the biggest one?

// Controls
static const float OFFSET_SPEED = 20.0f;
static const float X_SCALE_SPEED = 1.05f;
static const float Y_SCALE_SPEED = 1.05f;
static const float MIN_Y_SCALE = 0.8f;

#define INITIAL_VECTOR_CAPACITY 16

#define VECTOR_TYPEDEF(name, type) \
    typedef struct {               \
        size_t capacity;           \
        size_t length;             \
        type *data;                \
    } name

// TODO: check that vec is not null
#define VECTOR_PUSH(vec, element)                                                       \
    do {                                                                                \
        if ((vec)->capacity == 0) {                                                     \
            (vec)->capacity = INITIAL_VECTOR_CAPACITY;                                  \
            (vec)->data = malloc((vec)->capacity * sizeof(*(vec)->data));               \
            if ((vec)->data == NULL) exit(EXIT_FAILURE); /* // TODO: out-of-memory */   \
        } else if ((vec)->capacity == (vec)->length) {                                  \
            (vec)->capacity *= 2;                                                       \
            (vec)->data = realloc((vec)->data, (vec)->capacity * sizeof(*(vec)->data)); \
            if ((vec)->data == NULL) exit(EXIT_FAILURE); /* // TODO: out-of-memory */   \
        }                                                                               \
        (vec)->data[(vec)->length++] = (element);                                       \
    } while (0)

// TODO: check that vec is not null
#define VECTOR_FREE(vec)                                                          \
    do {                                                                          \
        if ((vec)->data == NULL) exit(EXIT_FAILURE); /* // TODO: error message */ \
        free((vec)->data);                                                        \
    } while (0)

typedef struct {
    int time_s;
    uint64_t ts_ns;
    int32_t cgroup;
    uint32_t latency_ns;
} Entry;

VECTOR_TYPEDEF(EntryVec, Entry);

typedef struct {
    uint64_t ts_us;
    uint32_t latency_us;
} Point;

VECTOR_TYPEDEF(PointVec, Point);

typedef struct {
    bool is_enabled;
    int32_t cgroup;
    Color color;
    uint64_t min_ts_us;
    uint64_t max_ts_us;
    uint32_t min_latency_us;
    uint32_t max_latency_us;
    PointVec points;
} Cgroup;

VECTOR_TYPEDEF(CgroupVec, Cgroup);

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

// TODO: reorder functions

// TODO: rename? read_output? read_data?
static void parse_output(EntryVec *entries, pid_t child, int fd) {
    assert(entries != NULL);

    // TODO: make non-static:
    static bool skipped_header = false;
    const int buffer_size = 512;  // TODO: resize + move
    static char buffer[512];      // TODO: must be able to hold at least on full line -> assumption
    static int buffer_offset = 0;

    ssize_t bytes;
    while ((bytes = read(fd, buffer + buffer_offset, buffer_size - buffer_offset)) > 0) {
        int length = buffer_offset + bytes;

        int i = 0;
        while (i < length) {
            int j = i;  // TODO: rename

            while (i < length && buffer[i] != '\n') i++;
            if (i == length) {
                buffer_offset = length - j;
                memmove(buffer, buffer + j, buffer_offset);
                break;
            }

            i++;  // go over that '\n'
            if (i == length) buffer_offset = 0;

            if (!skipped_header) {
                skipped_header = true;
                continue;
            }

            Entry entry = {0};
            const char *ch = buffer + j;

            // TIME
            ch = time_field(&entry.time_s, ch);
            assert(0 <= entry.time_s);

            // PREV_CGROUP
            ch = skip_field(ch);

            // CGROUP
            long long cgroup;
            ch = llong_field(&cgroup, ch);
            assert(0 <= cgroup && cgroup <= INT32_MAX);
            entry.cgroup = cgroup;

            // RUNQ_LATENCY
            long long latency_ns;
            ch = llong_field(&latency_ns, ch);
            assert(0 <= latency_ns && latency_ns <= UINT32_MAX);
            entry.latency_ns = latency_ns;

            // TS
            long long ts_ns;
            ch = llong_field(&ts_ns, ch);
            assert(0 <= ts_ns);
            entry.ts_ns = ts_ns;

            assert(*ch == '\n');

            VECTOR_PUSH(entries, entry);
        }
    }

    if (bytes == 0) {
        // TODO: do this outside if this functions returns 1?
        int status;
        waitpid(child, &status, 0);
        status = WEXITSTATUS(status);

        // TODO: what if status == 0?
        if (status == ENOENT) fprintf(stderr, "ERROR: unable to find \"ecli\" to run eBPF program.\n");
        else fprintf(stderr, "ERROR: eBPF process exited unexpectedly.\n");
        abort();  // TODO:
    }
    if (bytes == -1 && errno != EAGAIN) abort();  // TODO:
}

static void process_data(CgroupVec *cgroups, EntryVec entries, size_t *entries_idx) {
    assert(cgroups != NULL);

    size_t i;  // TODO: refactor
    for (i = *entries_idx; i < entries.length; i++) {
        Cgroup *cgroup = NULL;
        for (size_t j = 0; j < cgroups->length; j++) {
            if (entries.data[i].cgroup == cgroups->data[j].cgroup) {
                cgroup = &cgroups->data[j];
                break;
            }
        }

        if (cgroup == NULL) {
            Cgroup new_cgroup = {
                .is_enabled = true,
                .cgroup = entries.data[i].cgroup,
                .color = COLORS[cgroups->length % COLORS_LEN],
                .min_ts_us = UINT64_MAX,
                .max_ts_us = 0,
                .min_latency_us = UINT32_MAX,
                .max_latency_us = 0,
                .points = {0},
            };
            VECTOR_PUSH(cgroups, new_cgroup);
            cgroup = &cgroups->data[cgroups->length - 1];
        }

        uint64_t latency_us = entries.data[i].latency_ns / 1000;
        uint32_t ts_us = entries.data[i].ts_ns / 1000;

        cgroup->min_ts_us = MIN(cgroup->min_ts_us, ts_us);
        cgroup->max_ts_us = MAX(cgroup->max_ts_us, ts_us);
        cgroup->min_latency_us = MIN(cgroup->min_latency_us, latency_us);
        cgroup->max_latency_us = MAX(cgroup->max_latency_us, latency_us);

        // TODO: batch & average

        Point point = {
            .latency_us = latency_us,
            .ts_us = ts_us,
        };
        VECTOR_PUSH(&cgroup->points, point);
    }
    *entries_idx = i;

    size_t l = 0, r = cgroups->length - 1;
    while (l < r) {
        while (l < r && cgroups->data[l].points.length >= CGROUP_MIN_POINTS) l++;
        while (l < r && cgroups->data[r].points.length < CGROUP_MIN_POINTS) r--;
        if (l < r) {
            Cgroup temp = cgroups->data[l];
            cgroups->data[l] = cgroups->data[r];
            cgroups->data[r] = temp;
            l++;
            r--;
        }
    }
}

static bool button(Rectangle rec) {
    bool is_mouse_over = CheckCollisionPointRec(GetMousePosition(), rec);
    if (!is_mouse_over) return false;

    SetMouseCursor(MOUSE_CURSOR_POINTING_HAND);
    return IsMouseButtonPressed(MOUSE_BUTTON_LEFT);
}

static int start_ebpf(int *ret_read_fd, pid_t *child) {
    int fds[2];
    if (pipe(fds) == -1) return 1;
    int read_fd = fds[0];
    int write_fd = fds[1];

    if (prctl(PR_SET_PDEATHSIG, SIGTERM) == -1) return 1;

    pid_t pid = fork();
    if (pid == -1) return 1;
    *child = pid;

    if (pid == 0) {
        // TODO: output on error?
        if (dup2(write_fd, fileno(stdout)) == -1) exit(EXIT_FAILURE);
        if (close(read_fd) != 0) exit(EXIT_FAILURE);
        execlp("ecli", "ecli", "run", "ebpf/package.json", (char *) NULL);
        if (errno == ENOENT) exit(ENOENT);
        exit(EXIT_FAILURE);
    }

    if (fcntl(read_fd, F_SETFL, fcntl(read_fd, F_GETFL) | O_NONBLOCK) == -1) return 1;
    if (close(write_fd) != 0) return 1;

    *ret_read_fd = read_fd;
    return 0;
}

int main(void) {
    if (RAYLIB_VERSION_MAJOR != 5) {
        fprintf(stderr, "ERROR: the required raylib version is 5.\n");
        return EXIT_FAILURE;
    }

    if (geteuid() != 0) {
        fprintf(stderr, "ERROR: must be ran as root.\n");
        return EXIT_FAILURE;
    }

    int input_fd;
    pid_t child;
    if (start_ebpf(&input_fd, &child) != 0) {
        fprintf(stderr, "ERROR: unable to start eBPF program.\n");
        return EXIT_FAILURE;
    }

    // TODO: dropping sudo privileges

    double offset = 0.0f;
    double x_scale = 1.0f;
    double y_scale = 1.0f;

    EntryVec entries = {0};
    CgroupVec cgroups = {0};

    SetTraceLogLevel(LOG_WARNING);
    InitWindow(WIDTH, HEIGHT, TITLE);
    SetTargetFPS(30);

    bool is_first_entry = true;
    bool running = true;     // TODO: rename
    size_t entries_idx = 0;  // TODO: move

    int min_time_s;
    int max_time_s;
    double time_per_px;
    uint64_t min_ts_us = UINT64_MAX;
    uint64_t max_ts_us = 0;
    uint32_t min_latency_us = UINT32_MAX;
    uint32_t max_latency_us = 0;
    double ts_per_px;
    double latency_per_px;
    while (!WindowShouldClose()) {
        if (running) {
            parse_output(&entries, child, input_fd);
            if (entries.length == 0) continue;

            if (is_first_entry) {
                is_first_entry = false;
                min_time_s = entries.data[0].time_s;
            }

            max_time_s = entries.data[entries.length - 1].time_s;
            time_per_px = (max_time_s - min_time_s) / ((double) INNER_WIDTH);

            process_data(&cgroups, entries, &entries_idx);

            for (size_t i = 0; i < cgroups.length; i++) {
                min_ts_us = MIN(min_ts_us, cgroups.data[i].min_ts_us);
                max_ts_us = MAX(max_ts_us, cgroups.data[i].max_ts_us);
                min_latency_us = MIN(min_latency_us, cgroups.data[i].min_latency_us);
                max_latency_us = MAX(max_latency_us, cgroups.data[i].max_latency_us);
            }

            ts_per_px = (max_ts_us - min_ts_us) / ((double) INNER_WIDTH);
            latency_per_px = (max_latency_us - min_latency_us) / ((double) INNER_HEIGHT);
        }

        if (IsKeyDown(KEY_LEFT)) offset = MAX(offset - 1.0f / (x_scale * OFFSET_SPEED), 0.0f);
        if (IsKeyDown(KEY_RIGHT)) offset = MIN(offset + 1.0f / (OFFSET_SPEED * x_scale), 1.0f - 1.0f / x_scale);

        if (IsKeyDown(KEY_EQUAL)) x_scale *= X_SCALE_SPEED;
        if (IsKeyDown(KEY_MINUS)) {
            x_scale = MAX(x_scale / X_SCALE_SPEED, 1.0f);
            offset = MIN(offset, 1.0f - 1.0f / x_scale);
        }

        if (IsKeyDown(KEY_UP)) y_scale *= Y_SCALE_SPEED;
        if (IsKeyDown(KEY_DOWN)) y_scale = MAX(y_scale / Y_SCALE_SPEED, MIN_Y_SCALE);

        if (IsKeyPressed(KEY_SPACE)) {
            kill(child, SIGTERM);
            running = false;
        }

        BeginDrawing();
        ClearBackground(BACKGROUND);
        SetMouseCursor(MOUSE_CURSOR_DEFAULT);

        // TODO: start bpf and read output

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
        for (size_t i = 0; i < cgroups.length; i++) {
            Rectangle rec = {
                .x = w,
                .y = (TOP_PADDING - LEGEND_COLOR_SIZE) / 2,
                .width = LEGEND_COLOR_SIZE,
                .height = LEGEND_FONT_SIZE,
            };

            if (cgroups.data[i].is_enabled) {
                DrawRectangleRec(rec, cgroups.data[i].color);
            } else {
                DrawRectangleLinesEx(rec, LEGEND_COLOR_THICKNESS, cgroups.data[i].color);
            }
            w += LEGEND_COLOR_SIZE + LEGEND_COLOR_PADDING;

            bool is_clicked = button(rec);
            if (is_clicked) cgroups.data[i].is_enabled = !cgroups.data[i].is_enabled;

            snprintf(buffer, 256, "%d", cgroups.data[i].cgroup);
            Vector2 td = MeasureText2(buffer, LEGEND_FONT_SIZE);
            DrawText(buffer, w, (TOP_PADDING - td.y) / 2, LEGEND_FONT_SIZE, cgroups.data[i].color);
            w += td.x + LEGEND_PADDING;
        }

        for (size_t i = 0; i < cgroups.length; i++) {
            if (!cgroups.data[i].is_enabled) continue;
            Cgroup entry = cgroups.data[i];

            // TODO: refactor?
            int px = -1;
            int py = -1;
            int npx, npy;
            for (size_t j = 0; j < entry.points.length; j++, px = npx, py = npy) {
                Point point = entry.points.data[j];

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

    for (size_t i = 0; i < cgroups.length; i++) VECTOR_FREE(&cgroups.data[i].points);
    VECTOR_FREE(&cgroups);
    VECTOR_FREE(&entries);

    kill(child, SIGTERM);
    close(input_fd);

    return EXIT_SUCCESS;
}
