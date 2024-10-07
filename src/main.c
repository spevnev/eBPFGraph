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
static const int TOP_PADDING = 75;
static const int BOT_PADDING = 150;
#define INNER_WIDTH (WIDTH - 2 * HOR_PADDING)
#define INNER_HEIGHT (HEIGHT - TOP_PADDING - BOT_PADDING)
static const int GRID_SIZE = 60;
static const int AXIS_NAME_FONT_SIZE = 14;
static const int AXIS_VALUE_FONT_SIZE = 10;
static const int TEXT_MARGIN = 4;
static const int LEGEND_TOP_MARGIN = 25;
static const int LEGEND_COLOR_SIZE = 16;
static const int LEGEND_COLOR_PADDING = 4;
static const int LEGEND_COLOR_THICKNESS = 2;
static const int LEGEND_FONT_SIZE = 16;
static const int LEGEND_PADDING = 20;
static const int STATS_FONT_SIZE = 20;
static const int STATS_COLUMN_PADDING = 25;

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

#define VECTOR_LAST(vec) ((vec)->length > 0 ? &(vec)->data[(vec)->length - 1] : NULL)

#define VECTOR_FREE(vec)                                             \
    do {                                                             \
        if ((vec) != NULL && (vec)->data != NULL) free((vec)->data); \
    } while (0)

typedef struct {
    uint32_t time_s;
    uint64_t ts_ns;
    int32_t prev_cgroup;
    int32_t cgroup;
    uint32_t latency_ns;
} Entry;

VECTOR_TYPEDEF(EntryVec, Entry);

typedef struct {
    uint64_t ts_us;
    uint64_t total_latency_us;
    int count;
} Latency;

VECTOR_TYPEDEF(LatencyVec, Latency);

typedef struct {
    uint64_t ts_us;
    uint32_t count;
} Preempt;

VECTOR_TYPEDEF(PreemptVec, Preempt);

typedef struct {
    bool is_enabled;
    bool is_visible;
    int32_t cgroup;
    Color color;
    LatencyVec latencies;
    PreemptVec preempts;
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
            long long prev_cgroup;
            ch = llong_field(&prev_cgroup, ch);
            assert(0 <= prev_cgroup && prev_cgroup <= INT32_MAX);
            entry.prev_cgroup = prev_cgroup;

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

static Cgroup *get_or_create_cgroup(CgroupVec *cgroups, int32_t id) {
    for (size_t j = 0; j < cgroups->length; j++) {
        if (cgroups->data[j].cgroup == id) {
            return &cgroups->data[j];
        }
    }

    Cgroup new_cgroup = {
        .is_enabled = true,
        .is_visible = true,
        .cgroup = id,
        .color = COLORS[cgroups->length % COLORS_LEN],
        .latencies = {0},
        .preempts = {0},
    };

    VECTOR_PUSH(cgroups, new_cgroup);
    return &cgroups->data[cgroups->length - 1];
}

static void group_entries(uint32_t *max_latency_us, uint32_t *max_preempts, CgroupVec *cgroups, EntryVec entries) {
    assert(max_latency_us != NULL && max_preempts != NULL && cgroups != NULL);

    static size_t i = 0;
    while (i < entries.length) {
        uint64_t ts_us = entries.data[i].ts_ns / 1000;
        uint32_t latency_us = entries.data[i].latency_ns / 1000;

        Cgroup *prev_cgroup = get_or_create_cgroup(cgroups, entries.data[i].prev_cgroup);
        Preempt *last_preempt = VECTOR_LAST(&prev_cgroup->preempts);
        if (last_preempt != NULL && ts_us - last_preempt->ts_us < CGROUP_BATCHING_TIME_US) {
            last_preempt->count++;
            *max_preempts = MAX(*max_preempts, last_preempt->count);
        } else {
            Preempt preempt = {
                .ts_us = ts_us,
                .count = 1,
            };
            VECTOR_PUSH(&prev_cgroup->preempts, preempt);
        }

        Cgroup *cgroup = get_or_create_cgroup(cgroups, entries.data[i].cgroup);
        Latency *last_latency = VECTOR_LAST(&cgroup->latencies);
        if (last_latency != NULL && ts_us - last_latency->ts_us < CGROUP_BATCHING_TIME_US) {
            last_latency->total_latency_us += latency_us;
            last_latency->count++;
            *max_latency_us = MAX(*max_latency_us, last_latency->total_latency_us / last_latency->count);
        } else {
            Latency latency = {
                .ts_us = ts_us,
                .total_latency_us = latency_us,
                .count = 1,
            };
            VECTOR_PUSH(&cgroup->latencies, latency);
        }

        i++;
    }

    for (size_t i = 0; i < cgroups->length; i++) {
        cgroups->data[i].is_visible = cgroups->data[i].latencies.length >= CGROUP_MIN_POINTS;
    }
}

static int draw_x_axis(double offset, double x_scale, uint32_t min_time_s, uint32_t max_time_s, uint64_t min_ts_us,
                       uint64_t max_ts_us, double time_per_px, double ts_per_px) {
    int max_y = 0;
    for (int i = 0; i <= INNER_WIDTH / GRID_SIZE; i++) {
        int x = i * GRID_SIZE + HOR_PADDING;
        int y = HEIGHT - BOT_PADDING + TEXT_MARGIN;

        DrawLine(x, TOP_PADDING, x, HEIGHT - BOT_PADDING, GRID_COLOR);

        uint64_t ts_us = min_ts_us + ts_per_px * i * GRID_SIZE / x_scale + (max_ts_us - min_ts_us) * offset;
        snprintf(buffer, BUFFER_SIZE, "%llu", (long long unsigned int) ts_us);
        Vector2 td = MeasureText2(buffer, AXIS_VALUE_FONT_SIZE);
        DrawText(buffer, x - td.x / 2, y, AXIS_VALUE_FONT_SIZE, FOREGROUND);
        y += td.y + TEXT_MARGIN;

        int time_s = min_time_s + time_per_px * i * GRID_SIZE / x_scale + (max_time_s - min_time_s) * offset;
        snprintf(buffer, BUFFER_SIZE, "%d:%02d:%02d", (time_s / 3600) % 24, (time_s / 60) % 60, time_s % 60);
        Vector2 td2 = MeasureText2(buffer, AXIS_VALUE_FONT_SIZE);
        DrawText(buffer, x - td2.x / 2, y, AXIS_VALUE_FONT_SIZE, FOREGROUND);
        y += td2.y + TEXT_MARGIN;

        max_y = MAX(max_y, y);
    }

    return max_y;
}

static void draw_y_axis(double latency_y_scale, double latency_per_px, double preempts_y_scale,
                        double preempts_per_px) {
    Vector2 td = MeasureText2("Latency (us)", AXIS_NAME_FONT_SIZE);
    DrawText("Latency (us)", HOR_PADDING - td.x / 2, TOP_PADDING - td.y - TEXT_MARGIN, AXIS_NAME_FONT_SIZE, FOREGROUND);

    td = MeasureText2("Preemptions", AXIS_NAME_FONT_SIZE);
    DrawText("Preemptions", WIDTH - HOR_PADDING - td.x / 2, TOP_PADDING - td.y - TEXT_MARGIN, AXIS_NAME_FONT_SIZE,
             FOREGROUND);

    for (int i = 0; i <= INNER_HEIGHT / GRID_SIZE; i++) {
        int y = HEIGHT - BOT_PADDING - GRID_SIZE * i;
        DrawLine(HOR_PADDING, y, WIDTH - HOR_PADDING, y, GRID_COLOR);

        uint32_t latency_us = latency_per_px * i * GRID_SIZE / latency_y_scale;
        snprintf(buffer, BUFFER_SIZE, "%u", (unsigned int) latency_us);
        td = MeasureText2(buffer, AXIS_VALUE_FONT_SIZE);
        DrawText(buffer, HOR_PADDING - td.x - TEXT_MARGIN, y - td.y / 2, AXIS_VALUE_FONT_SIZE, FOREGROUND);

        uint32_t preempts = preempts_per_px * i * GRID_SIZE / preempts_y_scale;
        snprintf(buffer, BUFFER_SIZE, "%u", (unsigned int) preempts);
        td = MeasureText2(buffer, AXIS_VALUE_FONT_SIZE);
        DrawText(buffer, WIDTH - HOR_PADDING + TEXT_MARGIN, y - td.y / 2, AXIS_VALUE_FONT_SIZE, FOREGROUND);
    }
}

static void draw_legend(CgroupVec cgroups) {
    int x = HOR_PADDING;
    for (size_t i = 0; i < cgroups.length; i++) {
        Cgroup *cgroup = &cgroups.data[i];
        if (!cgroup->is_visible) continue;

        Rectangle rec = {
            .x = x,
            .y = LEGEND_TOP_MARGIN - LEGEND_COLOR_SIZE / 2,
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
        DrawText(buffer, x, LEGEND_TOP_MARGIN - td.y / 2, LEGEND_FONT_SIZE, cgroups.data[i].color);
        x += td.x + LEGEND_PADDING;
    }
}

static void draw_graph_line(double px, double py, double x, double y, Color color) {
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

    DrawLine(HOR_PADDING + rpx, HEIGHT - BOT_PADDING - rpy, HOR_PADDING + rx, HEIGHT - BOT_PADDING - ry, color);
}

static void draw_graph(CgroupVec cgroups, double offset, double x_scale, double latency_y_scale,
                       double preempts_y_scale, uint64_t min_ts_us, uint64_t max_ts_us, double ts_per_px,
                       double latency_per_px, double preempts_per_px) {
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
        for (size_t j = 0; j < cgroup->latencies.length; j++, px = npx, py = npy) {
            Latency point = cgroup->latencies.data[j];
            uint32_t latency = point.total_latency_us / point.count;

            double x = (point.ts_us - min_ts_us - (max_ts_us - min_ts_us) * offset) / ts_per_px * x_scale;
            double y = latency / latency_per_px * latency_y_scale;

            npx = x;
            npy = y;

            if (px == -1) continue;
            if (x < 0) continue;
            if (x > INNER_WIDTH && px > INNER_WIDTH) break;
            if (y > INNER_HEIGHT && py > INNER_HEIGHT) continue;

            draw_graph_line(px, py, x, y, cgroup->color);

            cgroup->min_latency_us = MIN(cgroup->min_latency_us, latency);
            cgroup->max_latency_us = MAX(cgroup->max_latency_us, latency);
            cgroup->total_latency_us += latency;
            cgroup->count++;
        }

        px = -1;
        py = -1;
        for (size_t j = 0; j < cgroup->preempts.length; j++, px = npx, py = npy) {
            Preempt point = cgroup->preempts.data[j];

            double x = (point.ts_us - min_ts_us - (max_ts_us - min_ts_us) * offset) / ts_per_px * x_scale;
            double y = point.count / preempts_per_px * preempts_y_scale;

            npx = x;
            npy = y;

            if (px == -1) continue;
            if (x < 0) continue;
            if (x > INNER_WIDTH && px > INNER_WIDTH) break;
            if (y > INNER_HEIGHT && py > INNER_HEIGHT) continue;

            Vector3 hsv = ColorToHSV(cgroup->color);
            draw_graph_line(px, py, x, y, ColorFromHSV(hsv.x, hsv.y * 0.5f, hsv.z * 0.5f));
        }
    }
}

static void draw_stats(int start_y, CgroupVec cgroups) {
    Vector2 group_column_dim = MeasureText2("Group", STATS_FONT_SIZE);
    int group_column_width = group_column_dim.x;
    int min_column_width = MeasureText("Min", STATS_FONT_SIZE);
    int max_column_width = MeasureText("Max", STATS_FONT_SIZE);
    int avg_column_width = MeasureText("Avg", STATS_FONT_SIZE);
    for (size_t i = 0; i < cgroups.length; i++) {
        Cgroup cgroup = cgroups.data[i];
        if (!cgroup.is_visible || !cgroup.is_enabled) continue;

        snprintf(buffer, BUFFER_SIZE, "%d", cgroup.cgroup);
        group_column_width = MAX(group_column_width, MeasureText(buffer, STATS_FONT_SIZE));

        snprintf(buffer, BUFFER_SIZE, "%uus", cgroup.min_latency_us);
        min_column_width = MAX(min_column_width, MeasureText(buffer, STATS_FONT_SIZE));

        snprintf(buffer, BUFFER_SIZE, "%uus", cgroup.max_latency_us);
        max_column_width = MAX(max_column_width, MeasureText(buffer, STATS_FONT_SIZE));

        uint32_t avg = cgroup.total_latency_us / cgroup.count;
        snprintf(buffer, BUFFER_SIZE, "%uus", avg);
        avg_column_width = MAX(avg_column_width, MeasureText(buffer, STATS_FONT_SIZE));
    }

    int group_column_x = HOR_PADDING;
    int min_column_x = group_column_x + group_column_width + STATS_COLUMN_PADDING;
    int max_column_x = min_column_x + min_column_width + STATS_COLUMN_PADDING;
    int avg_column_x = max_column_x + max_column_width + STATS_COLUMN_PADDING;

    int y = start_y;
    DrawText("Group", group_column_x, y, STATS_FONT_SIZE, FOREGROUND);
    DrawText("Min", min_column_x, y, STATS_FONT_SIZE, FOREGROUND);
    DrawText("Max", max_column_x, y, STATS_FONT_SIZE, FOREGROUND);
    DrawText("Avg", avg_column_x, y, STATS_FONT_SIZE, FOREGROUND);
    y += group_column_dim.y + TEXT_MARGIN;

    for (size_t i = 0; i < cgroups.length; i++) {
        Cgroup cgroup = cgroups.data[i];
        if (!cgroup.is_visible || !cgroup.is_enabled) continue;

        snprintf(buffer, BUFFER_SIZE, "%d", cgroup.cgroup);
        Vector2 td = MeasureText2(buffer, STATS_FONT_SIZE);
        DrawText(buffer, group_column_x, y, STATS_FONT_SIZE, cgroup.color);

        snprintf(buffer, BUFFER_SIZE, "%uus", cgroup.min_latency_us);
        DrawText(buffer, min_column_x, y, STATS_FONT_SIZE, FOREGROUND);

        snprintf(buffer, BUFFER_SIZE, "%uus", cgroup.max_latency_us);
        DrawText(buffer, max_column_x, y, STATS_FONT_SIZE, FOREGROUND);

        uint32_t avg = cgroup.total_latency_us / cgroup.count;
        snprintf(buffer, BUFFER_SIZE, "%uus", avg);
        DrawText(buffer, avg_column_x, y, STATS_FONT_SIZE, FOREGROUND);

        y += td.y + TEXT_MARGIN;
        if (y >= HEIGHT) break;
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
    double latency_y_scale = 1.0f;
    double preempts_y_scale = 1.0f;

    EntryVec entries = {0};
    CgroupVec cgroups = {0};

    uint32_t min_time_s = UINT32_MAX;
    uint32_t max_time_s = 0;
    uint64_t min_ts_us = UINT64_MAX;
    uint64_t max_ts_us = 0;
    uint32_t max_latency_us = 0;
    uint32_t max_preempts = 0;
    double time_per_px = 0;
    double ts_per_px = 0;
    double latency_per_px = 0;
    double preempts_per_px = 0;

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

            // Updates max values
            group_entries(&max_latency_us, &max_preempts, &cgroups, entries);

            // Min latency and preemptions are assumed to be 0
            latency_per_px = max_latency_us / ((double) INNER_HEIGHT);
            preempts_per_px = max_preempts / ((double) INNER_HEIGHT);
        }

        // Controls

        if (IsKeyDown(KEY_LEFT)) offset = MAX(offset - 1.0f / (x_scale * OFFSET_SPEED), 0.0f);
        if (IsKeyDown(KEY_RIGHT)) offset = MIN(offset + 1.0f / (OFFSET_SPEED * x_scale), 1.0f - 1.0f / x_scale);

        if (IsKeyDown(KEY_EQUAL)) x_scale *= X_SCALE_SPEED;
        if (IsKeyDown(KEY_MINUS)) {
            x_scale = MAX(x_scale / X_SCALE_SPEED, 1.0f);
            offset = MIN(offset, 1.0f - 1.0f / x_scale);
        }

        if (IsKeyDown(KEY_UP)) {
            if (IsKeyDown(KEY_LEFT_SHIFT)) preempts_y_scale *= Y_SCALE_SPEED;
            else latency_y_scale *= Y_SCALE_SPEED;
        }
        if (IsKeyDown(KEY_DOWN)) {
            if (IsKeyDown(KEY_LEFT_SHIFT)) preempts_y_scale = MAX(preempts_y_scale / Y_SCALE_SPEED, MIN_Y_SCALE);
            else latency_y_scale = MAX(latency_y_scale / Y_SCALE_SPEED, MIN_Y_SCALE);
        }

        if (IsKeyPressed(KEY_SPACE)) kill(child, SIGTERM);

        // Drawing

        BeginDrawing();
        ClearBackground(BACKGROUND);
        SetMouseCursor(MOUSE_CURSOR_DEFAULT);

        int x_axis_max_y
            = draw_x_axis(offset, x_scale, min_time_s, max_time_s, min_ts_us, max_ts_us, time_per_px, ts_per_px);
        draw_y_axis(latency_y_scale, latency_per_px, preempts_y_scale, preempts_per_px);
        draw_legend(cgroups);
        draw_graph(cgroups, offset, x_scale, latency_y_scale, preempts_y_scale, min_ts_us, max_ts_us, ts_per_px,
                   latency_per_px, preempts_per_px);  // collects stats
        draw_stats(x_axis_max_y, cgroups);

        EndDrawing();
    }

    CloseWindow();

    for (size_t i = 0; i < cgroups.length; i++) {
        VECTOR_FREE(&cgroups.data[i].latencies);
        VECTOR_FREE(&cgroups.data[i].preempts);
    }
    VECTOR_FREE(&cgroups);
    VECTOR_FREE(&entries);

    kill(child, SIGTERM);
    close(input_fd);

    return EXIT_SUCCESS;
}
