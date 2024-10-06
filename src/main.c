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
static const int BOT_PADDING = 200;
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
static const int STATS_FONT_SIZE = 14;

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
static const size_t CGROUP_MIN_POINTS = 500;
static const uint64_t CGROUP_BATCHING_TIME_US = 100;

// Controls
static const float OFFSET_SPEED = 20.0f;
static const float X_SCALE_SPEED = 1.05f;
static const float Y_SCALE_SPEED = 1.05f;
static const float MIN_Y_SCALE = 0.9f;

// Temp buffer for snprintf-ing
#define BUFFER_SIZE 256
static char buffer[BUFFER_SIZE];

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
    uint32_t time_s;
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
    bool is_visible;
    int32_t cgroup;
    Color color;
    PointVec points;
    // Stats collected for each group over the visible area:
    uint32_t min_latency_us;
    uint32_t max_latency_us;
    uint64_t total_latency_us;
    int count;
} Cgroup;

VECTOR_TYPEDEF(CgroupVec, Cgroup);

#define MeasureText2(text, font_size) \
    MeasureTextEx(GetFontDefault(), (text), (font_size), (font_size) / GetFontDefault().baseSize)

#define MAX(a, b) ((a) >= (b) ? (a) : (b))
#define MIN(a, b) ((a) <= (b) ? (a) : (b))

static void start_ebpf(int *ret_read_fd, pid_t *child) {
    int fds[2];
    if (pipe(fds) == -1) ERROR("unable to create pipe.");
    int read_fd = fds[0];
    int write_fd = fds[1];

    if (prctl(PR_SET_PDEATHSIG, SIGTERM) == -1) ERROR("unable to set PDEATHSIG for eBPF process.");

    pid_t pid = fork();
    if (pid == -1) ERROR("unable to fork.");
    *child = pid;

    if (pid == 0) {
        if (dup2(write_fd, fileno(stdout)) == -1) exit(EXIT_FAILURE);
        if (close(read_fd) != 0) exit(EXIT_FAILURE);
        execlp("ecli", "ecli", "run", "ebpf/package.json", (char *) NULL);
        if (errno == ENOENT) exit(ENOENT);
        exit(EXIT_FAILURE);
    }

    if (close(write_fd) != 0) ERROR("unable to close pipe's write end.");
    if (fcntl(read_fd, F_SETFL, fcntl(read_fd, F_GETFL) | O_NONBLOCK) == -1) {
        ERROR("unable to make pipe's read end non-blocking.");
    }

    *ret_read_fd = read_fd;
}

static const char *skip_field(const char *ch) {
    assert(ch != NULL);

    while (*ch == ' ') ch++;
    while (*ch != ' ' && *ch != '\0') ch++;

    return ch;
}

static const char *time_field(uint32_t *ret_s, const char *ch) {
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

static uint32_t group_entries(CgroupVec *cgroups, EntryVec entries) {
    assert(cgroups != NULL);

    static size_t i = 0;

    uint32_t current_max_latency = 0;
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
                .points = {0},
            };
            VECTOR_PUSH(cgroups, new_cgroup);
            cgroup = &cgroups->data[cgroups->length - 1];
        }

        uint64_t ts_us = entries.data[i].ts_ns / 1000;
        uint32_t latency_us = entries.data[i].latency_ns / 1000;

        Point *last = cgroup->points.length > 0 ? &cgroup->points.data[cgroup->points.length - 1] : NULL;
        if (last != NULL && ts_us - last->ts_us < CGROUP_BATCHING_TIME_US) {
            last->total_latency_us += latency_us;
            last->count++;
        } else {
            if (last != NULL) {
                // This doesn't take the very last point into account
                current_max_latency = MAX(current_max_latency, last->total_latency_us / last->count);
            }

            Point point = {
                .ts_us = ts_us,
                .total_latency_us = latency_us,
                .count = 1,
            };
            VECTOR_PUSH(&cgroup->points, point);
        }

        i++;
    }

    for (size_t i = 0; i < cgroups->length; i++) {
        cgroups->data[i].is_visible = cgroups->data[i].points.length >= CGROUP_MIN_POINTS;
    }

    return current_max_latency;
}

int draw_x_axis(double offset, double x_scale, uint32_t min_time_s, uint32_t max_time_s, uint64_t min_ts_us,
                uint64_t max_ts_us, double time_per_px, double ts_per_px) {
    int max_y = 0;
    for (int i = 0; i <= INNER_WIDTH / GRID_SIZE; i++) {
        int x = i * GRID_SIZE + HOR_PADDING;
        int y = HEIGHT - BOT_PADDING + TEXT_MARGIN;

        DrawLine(x, TOP_PADDING, x, HEIGHT - BOT_PADDING, GRID_COLOR);

        uint64_t ts_us = min_ts_us + ts_per_px * i * GRID_SIZE / x_scale + (max_ts_us - min_ts_us) * offset;
        snprintf(buffer, BUFFER_SIZE, "%llu", (long long unsigned int) ts_us);
        Vector2 td = MeasureText2(buffer, AXIS_FONT_SIZE);
        DrawText(buffer, x - td.x / 2, y, AXIS_FONT_SIZE, FOREGROUND);
        y += td.y + TEXT_MARGIN;

        int time_s = min_time_s + time_per_px * i * GRID_SIZE / x_scale + (max_time_s - min_time_s) * offset;
        snprintf(buffer, BUFFER_SIZE, "%d:%02d:%02d", (time_s / 3600) % 24, (time_s / 60) % 60, time_s % 60);
        Vector2 td2 = MeasureText2(buffer, AXIS_FONT_SIZE);
        DrawText(buffer, x - td2.x / 2, y, AXIS_FONT_SIZE, FOREGROUND);
        y += td2.y + TEXT_MARGIN;

        max_y = MAX(max_y, y);
    }

    return max_y;
}

void draw_y_axis(double y_scale, double latency_per_px) {
    for (int i = 0; i <= INNER_HEIGHT / GRID_SIZE; i++) {
        int y = HEIGHT - BOT_PADDING - GRID_SIZE * i;
        DrawLine(HOR_PADDING, y, WIDTH - HOR_PADDING, y, GRID_COLOR);

        uint32_t latency_us = latency_per_px * i * GRID_SIZE / y_scale;
        snprintf(buffer, BUFFER_SIZE, "%u", (unsigned int) latency_us);
        Vector2 td = MeasureText2(buffer, AXIS_FONT_SIZE);
        DrawText(buffer, HOR_PADDING - td.x - TEXT_MARGIN, y - td.y / 2, AXIS_FONT_SIZE, FOREGROUND);
    }
}

void draw_legend(CgroupVec cgroups) {
    int x = HOR_PADDING;
    for (size_t i = 0; i < cgroups.length; i++) {
        Cgroup *cgroup = &cgroups.data[i];
        if (!cgroup->is_visible) continue;

        Rectangle rec = {
            .x = x,
            .y = (TOP_PADDING - LEGEND_COLOR_SIZE) / 2,
            .width = LEGEND_COLOR_SIZE,
            .height = LEGEND_FONT_SIZE,
        };

        if (cgroup->is_enabled) {
            DrawRectangleRec(rec, cgroup->color);
        } else {
            DrawRectangleLinesEx(rec, LEGEND_COLOR_THICKNESS, cgroup->color);
        }
        x += LEGEND_COLOR_SIZE + LEGEND_COLOR_PADDING;

        bool is_mouse_over = CheckCollisionPointRec(GetMousePosition(), rec);
        if (is_mouse_over) {
            SetMouseCursor(MOUSE_CURSOR_POINTING_HAND);

            if (IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
                if (IsKeyDown(KEY_LEFT_SHIFT)) {
                    for (size_t j = 0; j < cgroups.length; j++) cgroups.data[j].is_enabled = false;
                    cgroup->is_enabled = true;
                } else {
                    cgroup->is_enabled = !cgroup->is_enabled;
                }
            }
        }

        snprintf(buffer, BUFFER_SIZE, "%d", cgroups.data[i].cgroup);
        Vector2 td = MeasureText2(buffer, LEGEND_FONT_SIZE);
        DrawText(buffer, x, (TOP_PADDING - td.y) / 2, LEGEND_FONT_SIZE, cgroups.data[i].color);
        x += td.x + LEGEND_PADDING;
    }
}

void draw_graph(CgroupVec cgroups, double offset, double x_scale, double y_scale, uint64_t min_ts_us,
                uint64_t max_ts_us, double ts_per_px, double latency_per_px) {
    for (size_t i = 0; i < cgroups.length; i++) {
        Cgroup *cgroup = &cgroups.data[i];
        if (!cgroup->is_visible || !cgroup->is_enabled) continue;

        cgroup->min_latency_us = UINT32_MAX;
        cgroup->max_latency_us = 0;
        cgroup->total_latency_us = 0;
        cgroup->count = 0;

        double px = -1;
        double py = -1;
        double npx, npy;
        for (size_t j = 0; j < cgroup->points.length; j++, px = npx, py = npy) {
            Point point = cgroup->points.data[j];
            uint32_t latency = point.total_latency_us / point.count;

            double x = (point.ts_us - min_ts_us - (max_ts_us - min_ts_us) * offset) / ts_per_px * x_scale;
            double y = latency / latency_per_px * y_scale;

            npx = x;
            npy = y;

            if (x < 0) continue;
            if (x > INNER_WIDTH && px > INNER_WIDTH) break;
            if (y > INNER_HEIGHT && py > INNER_HEIGHT) continue;
            if (px == -1) continue;

            cgroup->min_latency_us = MIN(cgroup->min_latency_us, latency);
            cgroup->max_latency_us = MAX(cgroup->max_latency_us, latency);
            cgroup->total_latency_us += latency;
            cgroup->count++;

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
                     cgroup->color);
        }
    }
}

void draw_stats(int start_y, CgroupVec cgroups) {
    // TODO: render in columns
    // TODO: break on overflow
    // TODO: scrolling?

    int y = start_y;
    for (size_t i = 0; i < cgroups.length; i++) {
        Cgroup cgroup = cgroups.data[i];
        if (!cgroup.is_visible || !cgroup.is_enabled) continue;

        snprintf(buffer, BUFFER_SIZE, "%uus %uus %luus", cgroup.min_latency_us, cgroup.max_latency_us,
                 cgroup.total_latency_us / cgroup.count);
        DrawText(buffer, HOR_PADDING, y, STATS_FONT_SIZE, FOREGROUND);
        Vector2 td = MeasureText2(buffer, STATS_FONT_SIZE);
        y += td.y + TEXT_MARGIN;
    }
}

int main(void) {
    if (RAYLIB_VERSION_MAJOR != 5) ERROR("the required raylib version is 5.");

    if (geteuid() != 0) ERROR("must be ran as root.");

    bool is_child_running = true;
    int input_fd;
    pid_t child;
    start_ebpf(&input_fd, &child);

    double offset = 0.0f;
    double x_scale = 1.0f;
    double y_scale = 1.0f;

    EntryVec entries = {0};
    CgroupVec cgroups = {0};

    uint32_t min_time_s = UINT32_MAX;
    uint32_t max_time_s = 0;
    uint64_t min_ts_us = UINT64_MAX;
    uint64_t max_ts_us = 0;
    uint32_t max_latency_us = 0;
    double time_per_px = 0;
    double ts_per_px = 0;
    double latency_per_px = 0;

    SetTraceLogLevel(LOG_WARNING);
    InitWindow(WIDTH, HEIGHT, TITLE);
    SetTargetFPS(30);

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

            min_ts_us = entries.data[0].ts_ns / 1000;
            max_ts_us = entries.data[entries.length - 1].ts_ns / 1000;
            ts_per_px = (max_ts_us - min_ts_us) / ((double) INNER_WIDTH);

            min_time_s = entries.data[0].time_s;
            max_time_s = entries.data[entries.length - 1].time_s;
            time_per_px = (max_time_s - min_time_s) / ((double) INNER_WIDTH);

            uint32_t current_max_latency_us = group_entries(&cgroups, entries);

            // Min latency assumed to be 0
            max_latency_us = MAX(max_latency_us, current_max_latency_us);
            latency_per_px = max_latency_us / ((double) INNER_HEIGHT);
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

        int x_axis_max_y
            = draw_x_axis(offset, x_scale, min_time_s, max_time_s, min_ts_us, max_ts_us, time_per_px, ts_per_px);
        draw_y_axis(y_scale, latency_per_px);
        draw_legend(cgroups);
        draw_graph(cgroups, offset, x_scale, y_scale, min_ts_us, max_ts_us, ts_per_px,
                   latency_per_px);  // collects stats
        draw_stats(x_axis_max_y, cgroups);

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
