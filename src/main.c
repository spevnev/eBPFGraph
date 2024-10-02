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
static const Color COLORS[]
    = {{0xD8, 0x18, 0x18, 0xff}, {0x18, 0xD8, 0x18, 0xff}, {0x18, 0x18, 0xD8, 0xff}, {0x18, 0xD8, 0xD8, 0xff},
       {0xD8, 0x18, 0xD8, 0xff}, {0xD8, 0xD8, 0x18, 0xff}, {0xD8, 0x60, 0x60, 0xff}, {0x60, 0xD8, 0x60, 0xff},
       {0x60, 0x60, 0xD8, 0xff}, {0x60, 0xD8, 0xD8, 0xff}, {0xD8, 0x60, 0xD8, 0xff}, {0xD8, 0xD8, 0x60, 0xff}};
#define COLORS_LEN (sizeof(COLORS) / sizeof(*COLORS))

// Data processing
static const size_t CGROUP_MIN_POINTS = 500;  // TODO: percentage from the biggest one?
static const uint64_t CGROUP_BATCHING_TIME_US = 100;

// Controls
static const float OFFSET_SPEED = 20.0f;
static const float X_SCALE_SPEED = 1.05f;
static const float Y_SCALE_SPEED = 1.05f;
static const float MIN_Y_SCALE = 0.9f;

#define ERROR(...)                    \
    do {                              \
        fprintf(stderr, "ERROR: ");   \
        fprintf(stderr, __VA_ARGS__); \
        fprintf(stderr, "\n");        \
        exit(EXIT_FAILURE);           \
    } while (0)

#define INITIAL_VECTOR_CAPACITY 16

#define VECTOR_TYPEDEF(name, type) \
    typedef struct {               \
        size_t capacity;           \
        size_t length;             \
        type *data;                \
    } name

#define VECTOR_PUSH(vec, element)                                                       \
    do {                                                                                \
        assert((vec) != NULL);                                                          \
        if ((vec)->capacity == 0) {                                                     \
            (vec)->capacity = INITIAL_VECTOR_CAPACITY;                                  \
            (vec)->data = malloc((vec)->capacity * sizeof(*(vec)->data));               \
            if ((vec)->data == NULL) ERROR("out of memory.");                           \
        } else if ((vec)->capacity == (vec)->length) {                                  \
            (vec)->capacity *= 2;                                                       \
            (vec)->data = realloc((vec)->data, (vec)->capacity * sizeof(*(vec)->data)); \
            if ((vec)->data == NULL) ERROR("out of memory.");                           \
        }                                                                               \
        (vec)->data[(vec)->length++] = (element);                                       \
    } while (0)

#define VECTOR_FREE(vec)                              \
    do {                                              \
        assert((vec) != NULL && (vec)->data != NULL); \
        free((vec)->data);                            \
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
    uint64_t total_latency_us;
    int count;
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


static int read_entries(EntryVec *entries, int fd) {
    assert(entries != NULL);

    // Must hold at least one line
    static char buffer[1024];
    static int buffer_offset = 0;
    static bool skipped_header = false;

    ssize_t bytes;
    while ((bytes = read(fd, buffer + buffer_offset, sizeof(buffer) - buffer_offset)) > 0) {
        int length = buffer_offset + bytes;

        int i = 0;
        while (i < length) {
            int line_idx = i;

            while (i < length && buffer[i] != '\n') i++;
            if (i == length) {
                buffer_offset = length - line_idx;
                memmove(buffer, buffer + line_idx, buffer_offset);
                break;
            }

            i++;  // go over '\n'
            if (i == length) buffer_offset = 0;

            if (!skipped_header) {
                skipped_header = true;
                continue;
            }

            Entry entry = {0};
            const char *ch = buffer + line_idx;

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
    if (bytes == -1 && errno != EAGAIN) ERROR("unable to read from eBPF process.");
    if (bytes == 0) return -1;

    return 0;
}

static void group_entries(CgroupVec *cgroups, EntryVec entries) {
    assert(cgroups != NULL);

    static size_t i = 0;
    while (i < entries.length) {
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

        uint64_t ts_us = entries.data[i].ts_ns / 1000;
        uint32_t latency_us = entries.data[i].latency_ns / 1000;

        cgroup->min_ts_us = MIN(cgroup->min_ts_us, ts_us);
        cgroup->max_ts_us = MAX(cgroup->max_ts_us, ts_us);
        cgroup->min_latency_us = MIN(cgroup->min_latency_us, latency_us);
        cgroup->max_latency_us = MAX(cgroup->max_latency_us, latency_us);

        if (cgroup->points.length > 0
            && ts_us - cgroup->points.data[cgroup->points.length - 1].ts_us < CGROUP_BATCHING_TIME_US) {
            Point *last = &cgroup->points.data[cgroup->points.length - 1];
            last->total_latency_us += latency_us;
            last->count++;
        } else {
            Point point = {
                .ts_us = ts_us,
                .total_latency_us = latency_us,
                .count = 1,
            };
            VECTOR_PUSH(&cgroup->points, point);
        }

        i++;
    }

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

    bool is_child_running = true;

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
        // Data
        if (is_child_running) {
            if (read_entries(&entries, input_fd) != 0) {
                int status;
                waitpid(child, &status, 0);
                status = WEXITSTATUS(status);

                if (status == 0) {
                    is_child_running = false;
                } else if (status == ENOENT) {
                    ERROR("unable to find \"ecli\" to run eBPF program.");
                } else {
                    ERROR("eBPF process exited unexpectedly.");
                }
            }
            if (entries.length == 0) continue;

            min_time_s = entries.data[0].time_s;
            max_time_s = entries.data[entries.length - 1].time_s;
            time_per_px = (max_time_s - min_time_s) / ((double) INNER_WIDTH);

            group_entries(&cgroups, entries);

            for (size_t i = 0; i < cgroups.length; i++) {
                min_ts_us = MIN(min_ts_us, cgroups.data[i].min_ts_us);
                max_ts_us = MAX(max_ts_us, cgroups.data[i].max_ts_us);
                min_latency_us = MIN(min_latency_us, cgroups.data[i].min_latency_us);
                max_latency_us = MAX(max_latency_us, cgroups.data[i].max_latency_us);
            }

            ts_per_px = (max_ts_us - min_ts_us) / ((double) INNER_WIDTH);
            latency_per_px = (max_latency_us - min_latency_us) / ((double) INNER_HEIGHT);
        }

        // Controls

        if (IsKeyDown(KEY_LEFT)) offset = MAX(offset - 1.0f / (x_scale * OFFSET_SPEED), 0.0f);
        if (IsKeyDown(KEY_RIGHT)) offset = MIN(offset + 1.0f / (OFFSET_SPEED * x_scale), 1.0f - 1.0f / x_scale);

        if (IsKeyDown(KEY_EQUAL)) x_scale *= X_SCALE_SPEED;
        if (IsKeyDown(KEY_MINUS)) {
            x_scale = MAX(x_scale / X_SCALE_SPEED, 1.0f);
            offset = MIN(offset, 1.0f - 1.0f / x_scale);
        }

        if (IsKeyDown(KEY_UP)) y_scale *= Y_SCALE_SPEED;
        if (IsKeyDown(KEY_DOWN)) y_scale = MAX(y_scale / Y_SCALE_SPEED, MIN_Y_SCALE);

        if (IsKeyPressed(KEY_SPACE)) kill(child, SIGTERM);

        // Drawing

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
            if (is_clicked) {
                if (IsKeyDown(KEY_LEFT_SHIFT)) {
                    for (size_t j = 0; j < cgroups.length; j++) cgroups.data[j].is_enabled = false;
                    cgroups.data[i].is_enabled = true;
                } else {
                    cgroups.data[i].is_enabled = !cgroups.data[i].is_enabled;
                }
            }

            snprintf(buffer, 256, "%d", cgroups.data[i].cgroup);
            Vector2 td = MeasureText2(buffer, LEGEND_FONT_SIZE);
            DrawText(buffer, w, (TOP_PADDING - td.y) / 2, LEGEND_FONT_SIZE, cgroups.data[i].color);
            w += td.x + LEGEND_PADDING;
        }

        for (size_t i = 0; i < cgroups.length; i++) {
            if (!cgroups.data[i].is_enabled) continue;
            Cgroup entry = cgroups.data[i];

            double px = -1;
            double py = -1;
            double npx, npy;
            for (size_t j = 0; j < entry.points.length; j++, px = npx, py = npy) {
                Point point = entry.points.data[j];

                double x = (point.ts_us - min_ts_us - (max_ts_us - min_ts_us) * offset) / ts_per_px * x_scale;
                double y = (point.total_latency_us / point.count - min_latency_us) / latency_per_px * y_scale;

                npx = x;
                npy = y;

                if (x < 0) continue;
                if (x > INNER_WIDTH && px > INNER_WIDTH) break;
                if (y > INNER_HEIGHT && py > INNER_HEIGHT) continue;
                if (px == -1) continue;

                double rpx = px;
                double rpy = py;
                double rx = x;
                double ry = y;

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
