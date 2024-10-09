#define _DEFAULT_SOURCE
#include <assert.h>
#include <dirent.h>
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
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

// Window
static const char *TITLE = "eBPF Graph";
static const int WIDTH = 1600;
static const int HEIGHT = 900;

// Graph
static const int HOR_PADDING = 60;
static const int TOP_PADDING = 75;
static const int BOT_PADDING = 200;
#define INNER_WIDTH (WIDTH - 2 * HOR_PADDING)
#define INNER_HEIGHT (HEIGHT - TOP_PADDING - BOT_PADDING)
static const int GRID_SIZE = 60;

// Axes
static const int AXIS_LABEL_FONT_SIZE = 14;
static const int AXIS_DATA_FONT_SIZE = 10;
static const int TEXT_MARGIN = 4;

// Legend
static const int LEGEND_TOP_MARGIN = 25;
static const int LEGEND_COLOR_SIZE = 16;
static const int LEGEND_COLOR_PADDING = 4;
static const int LEGEND_COLOR_THICKNESS = 2;
static const int LEGEND_FONT_SIZE = 16;
static const int LEGEND_PADDING = 20;

// Stats
static const int STATS_LABEL_FONT_SIZE = 20;
static const int STATS_DATA_FONT_SIZE = 18;
static const int STATS_COLUMN_PADDING = 20;

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
static const size_t CGROUP_MIN_POINTS = 200;
static const uint64_t CGROUP_BATCHING_TIME_MS = 5;

// Controls
static const float OFFSET_SPEED = 20.0f;
static const float X_SCALE_SPEED = 1.07f;
static const float Y_SCALE_SPEED = 1.07f;
static const float MIN_Y_SCALE = 0.5f;

// Buffers
static const int CGROUP_PATH_PREFIX_LENGTH = 14;  // = strlen("/sys/fs/cgroup");
#define PATH_BUFFER_SIZE 4096
#define BUFFER_SIZE 256
static char buffer[BUFFER_SIZE];  // global temp buffer for snprintf-ing

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
    uint64_t id;
    char *name;
} CgroupName;

VECTOR_TYPEDEF(CgroupNameVec, CgroupName);

typedef struct {
    uint32_t time_s;
    uint64_t ts_ns;
    uint64_t prev_cgroup_id;
    uint64_t cgroup_id;
    uint64_t latency_ns;
} Entry;

VECTOR_TYPEDEF(EntryVec, Entry);

typedef struct {
    uint64_t ts_ms;
    uint64_t total_latency_ms;
    int count;
} Latency;

VECTOR_TYPEDEF(LatencyVec, Latency);

typedef struct {
    uint64_t ts_ms;
    uint32_t count;
} Preempt;

VECTOR_TYPEDEF(PreemptVec, Preempt);

typedef struct {
    bool is_enabled;
    bool is_visible;
    uint64_t id;
    Color color;
    LatencyVec latencies;
    PreemptVec preempts;
    // Stats collected for each cgroup over the visible area:
    uint32_t min_latency_ms;
    uint32_t max_latency_ms;
    uint64_t total_latency_ms;
    int latency_count;
    uint32_t min_preempts;
    uint32_t max_preempts;
    uint64_t total_preempts;
    int preempts_count;
} Cgroup;

VECTOR_TYPEDEF(CgroupVec, Cgroup);

#define MeasureText2(text, font_size) \
    MeasureTextEx(GetFontDefault(), (text), (font_size), (font_size) / GetFontDefault().baseSize)

#define MAX(a, b) ((a) >= (b) ? (a) : (b))
#define MIN(a, b) ((a) <= (b) ? (a) : (b))

static void collect_cgroup_names(CgroupNameVec *cgroup_names, char *path) {
    struct stat stats;
    if (stat(path, &stats) == -1) ERROR("unable to stat \"%s\".", path);

    CgroupName cgroup = {
        .id = stats.st_ino,
        .name = strdup(path + CGROUP_PATH_PREFIX_LENGTH),
    };
    VECTOR_PUSH(cgroup_names, cgroup);

    DIR *dir = opendir(path);
    if (!dir) ERROR("unable to open \"%s\".", path);

    size_t path_len = strlen(path);

    struct dirent *dirent;
    while ((dirent = readdir(dir)) != NULL) {
        if (strcmp(dirent->d_name, ".") == 0 || strcmp(dirent->d_name, "..") == 0) continue;
        if (dirent->d_type != DT_DIR) continue;

        size_t dir_len = strlen(dirent->d_name);
        assert(path_len + dir_len + 1 < PATH_BUFFER_SIZE);
        memcpy(path + path_len, dirent->d_name, dir_len);
        path[path_len + dir_len] = '/';
        path[path_len + dir_len + 1] = '\0';

        collect_cgroup_names(cgroup_names, path);
    }
    closedir(dir);
}

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

static const char *u64_field(uint64_t *ret, const char *ch) {
    assert(ret != NULL && ch != NULL);

    while (*ch == ' ') ch++;

    char *end = NULL;
    *ret = strtoull(ch, &end, 10);
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
            ch = time_field(&entry.time_s, ch);
            ch = u64_field(&entry.prev_cgroup_id, ch);
            ch = u64_field(&entry.cgroup_id, ch);
            ch = u64_field(&entry.latency_ns, ch);
            ch = u64_field(&entry.ts_ns, ch);
            assert(*ch == '\n');

            VECTOR_PUSH(entries, entry);
        }
    }
    if (bytes == -1 && errno != EAGAIN) ERROR("unable to read from eBPF process.");
    if (bytes == 0) return -1;

    return 0;
}

static Cgroup *get_or_create_cgroup(CgroupVec *cgroups, uint64_t id) {
    for (size_t j = 0; j < cgroups->length; j++) {
        if (cgroups->data[j].id == id) {
            return &cgroups->data[j];
        }
    }

    Cgroup new_cgroup = {
        .is_enabled = true,
        .is_visible = true,
        .id = id,
        .color = COLORS[cgroups->length % COLORS_LEN],
        .latencies = {0},
        .preempts = {0},
    };

    VECTOR_PUSH(cgroups, new_cgroup);
    return &cgroups->data[cgroups->length - 1];
}

static void group_entries(uint32_t *max_latency_ms, uint32_t *max_preempts, CgroupVec *cgroups, EntryVec entries) {
    assert(max_latency_ms != NULL && max_preempts != NULL && cgroups != NULL);

    static size_t i = 0;
    while (i < entries.length) {
        uint64_t ts_ms = entries.data[i].ts_ns / 1000000;
        uint32_t latency_ms = entries.data[i].latency_ns / 1000000;

        Cgroup *prev_cgroup = get_or_create_cgroup(cgroups, entries.data[i].prev_cgroup_id);
        Preempt *last_preempt = VECTOR_LAST(&prev_cgroup->preempts);
        if (last_preempt != NULL && ts_ms - last_preempt->ts_ms < CGROUP_BATCHING_TIME_MS) {
            last_preempt->count++;
            *max_preempts = MAX(*max_preempts, last_preempt->count);
        } else {
            Preempt preempt = {
                .ts_ms = ts_ms,
                .count = 1,
            };
            VECTOR_PUSH(&prev_cgroup->preempts, preempt);
        }

        Cgroup *cgroup = get_or_create_cgroup(cgroups, entries.data[i].cgroup_id);
        Latency *last_latency = VECTOR_LAST(&cgroup->latencies);
        if (last_latency != NULL && ts_ms - last_latency->ts_ms < CGROUP_BATCHING_TIME_MS) {
            last_latency->total_latency_ms += latency_ms;
            last_latency->count++;
            *max_latency_ms = MAX(*max_latency_ms, last_latency->total_latency_ms / last_latency->count);
        } else {
            Latency latency = {
                .ts_ms = ts_ms,
                .total_latency_ms = latency_ms,
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

static int draw_x_axis(double offset, double x_scale, uint32_t min_time_s, uint32_t max_time_s, uint64_t min_ts_ms,
                       uint64_t max_ts_ms, double time_per_px, double ts_per_px) {
    int max_y = 0;
    for (int i = 0; i <= INNER_WIDTH / GRID_SIZE; i++) {
        int x = i * GRID_SIZE + HOR_PADDING;
        int y = HEIGHT - BOT_PADDING + TEXT_MARGIN;

        DrawLine(x, TOP_PADDING, x, HEIGHT - BOT_PADDING, GRID_COLOR);

        uint64_t ts_ms = min_ts_ms + ts_per_px * i * GRID_SIZE / x_scale + (max_ts_ms - min_ts_ms) * offset;
        snprintf(buffer, BUFFER_SIZE, "%llu", (long long unsigned int) ts_ms);
        Vector2 td = MeasureText2(buffer, AXIS_DATA_FONT_SIZE);
        DrawText(buffer, x - td.x / 2, y, AXIS_DATA_FONT_SIZE, FOREGROUND);
        y += td.y + TEXT_MARGIN;

        int time_s = min_time_s + time_per_px * i * GRID_SIZE / x_scale + (max_time_s - min_time_s) * offset;
        snprintf(buffer, BUFFER_SIZE, "%d:%02d:%02d", (time_s / 3600) % 24, (time_s / 60) % 60, time_s % 60);
        Vector2 td2 = MeasureText2(buffer, AXIS_DATA_FONT_SIZE);
        DrawText(buffer, x - td2.x / 2, y, AXIS_DATA_FONT_SIZE, FOREGROUND);
        y += td2.y + TEXT_MARGIN;

        max_y = MAX(max_y, y);
    }

    return max_y;
}

static void draw_y_axis(double latency_y_scale, double latency_per_px, double preempts_y_scale,
                        double preempts_per_px) {
    Vector2 td = MeasureText2("Latency (ms)", AXIS_LABEL_FONT_SIZE);
    DrawText("Latency (ms)", HOR_PADDING - td.x / 2, TOP_PADDING - td.y - TEXT_MARGIN, AXIS_LABEL_FONT_SIZE,
             FOREGROUND);

    td = MeasureText2("Preemptions", AXIS_LABEL_FONT_SIZE);
    DrawText("Preemptions", WIDTH - HOR_PADDING - td.x / 2, TOP_PADDING - td.y - TEXT_MARGIN, AXIS_LABEL_FONT_SIZE,
             FOREGROUND);

    for (int i = 0; i <= INNER_HEIGHT / GRID_SIZE; i++) {
        int y = HEIGHT - BOT_PADDING - GRID_SIZE * i;
        DrawLine(HOR_PADDING, y, WIDTH - HOR_PADDING, y, GRID_COLOR);

        uint32_t latency_ms = latency_per_px * i * GRID_SIZE / latency_y_scale;
        snprintf(buffer, BUFFER_SIZE, "%u", (unsigned int) latency_ms);
        td = MeasureText2(buffer, AXIS_DATA_FONT_SIZE);
        DrawText(buffer, HOR_PADDING - td.x - TEXT_MARGIN, y - td.y / 2, AXIS_DATA_FONT_SIZE, FOREGROUND);

        uint32_t preempts = preempts_per_px * i * GRID_SIZE / preempts_y_scale;
        snprintf(buffer, BUFFER_SIZE, "%u", (unsigned int) preempts);
        td = MeasureText2(buffer, AXIS_DATA_FONT_SIZE);
        DrawText(buffer, WIDTH - HOR_PADDING + TEXT_MARGIN, y - td.y / 2, AXIS_DATA_FONT_SIZE, FOREGROUND);
    }
}

static const char *get_cgroup_name(CgroupNameVec cgroup_names, uint64_t id) {
    const char *name = NULL;
    for (size_t j = 0; j < cgroup_names.length; j++) {
        if (cgroup_names.data[j].id == id) {
            name = cgroup_names.data[j].name;
            break;
        }
    }
    assert(name != NULL);  // TODO: this is possible if cgroup was created after indexing them -> reindex
    return name;
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
            .height = LEGEND_COLOR_SIZE,
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

        snprintf(buffer, BUFFER_SIZE, "%lu", cgroup->id);
        Vector2 td = MeasureText2(buffer, LEGEND_FONT_SIZE);
        DrawText(buffer, x, LEGEND_TOP_MARGIN - td.y / 2, LEGEND_FONT_SIZE, cgroup->color);
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

static void draw_graph(bool draw_latency, bool draw_preempts, CgroupVec cgroups, double offset, double x_scale,
                       double latency_y_scale, double preempts_y_scale, uint64_t min_ts_ms, uint64_t max_ts_ms,
                       double ts_per_px, double latency_per_px, double preempts_per_px) {
    for (size_t i = 0; i < cgroups.length; i++) {
        Cgroup *cgroup = &cgroups.data[i];
        if (!cgroup->is_visible || !cgroup->is_enabled) continue;

        double npx, npy, px, py;

        if (draw_latency) {
            // Reset stats
            cgroup->min_latency_ms = UINT32_MAX;
            cgroup->max_latency_ms = 0;
            cgroup->total_latency_ms = 0;
            cgroup->latency_count = 0;

            px = -1;
            py = -1;
            for (size_t j = 0; j < cgroup->latencies.length; j++, px = npx, py = npy) {
                Latency point = cgroup->latencies.data[j];

                double x = (point.ts_ms - min_ts_ms - (max_ts_ms - min_ts_ms) * offset) / ts_per_px * x_scale;
                double y = (point.total_latency_ms / point.count) / latency_per_px * latency_y_scale;

                npx = x;
                npy = y;

                if (px == -1) continue;
                if (x < 0) continue;
                if (x > INNER_WIDTH && px > INNER_WIDTH) break;
                if (y > INNER_HEIGHT && py > INNER_HEIGHT) continue;

                draw_graph_line(px, py, x, y, cgroup->color);

                uint32_t latency = point.total_latency_ms / point.count;
                cgroup->min_latency_ms = MIN(cgroup->min_latency_ms, latency);
                cgroup->max_latency_ms = MAX(cgroup->max_latency_ms, latency);
                cgroup->total_latency_ms += latency;
                cgroup->latency_count++;
            }
        }

        if (draw_preempts) {
            // Reset stats
            cgroup->min_preempts = UINT32_MAX;
            cgroup->max_preempts = 0;
            cgroup->total_preempts = 0;
            cgroup->preempts_count = 0;

            px = -1;
            py = -1;
            for (size_t j = 0; j < cgroup->preempts.length; j++, px = npx, py = npy) {
                Preempt point = cgroup->preempts.data[j];

                double x = (point.ts_ms - min_ts_ms - (max_ts_ms - min_ts_ms) * offset) / ts_per_px * x_scale;
                double y = point.count / preempts_per_px * preempts_y_scale;

                npx = x;
                npy = y;

                if (px == -1) continue;
                if (x < 0) continue;
                if (x > INNER_WIDTH && px > INNER_WIDTH) break;
                if (y > INNER_HEIGHT && py > INNER_HEIGHT) continue;

                Vector3 hsv = ColorToHSV(cgroup->color);
                draw_graph_line(px, py, x, y, ColorFromHSV(hsv.x, hsv.y * 0.5f, hsv.z * 0.5f));

                cgroup->min_preempts = MIN(cgroup->min_preempts, point.count);
                cgroup->max_preempts = MAX(cgroup->max_preempts, point.count);
                cgroup->total_preempts += point.count;
                cgroup->preempts_count++;
            }
        }
    }
}

static void draw_stats(int start_y, CgroupVec cgroups, CgroupNameVec cgroup_names) {
    Vector2 id_column_dim = MeasureText2("Id", STATS_LABEL_FONT_SIZE);
    int id_column_width = id_column_dim.x;
    int name_column_width = MeasureText("Name", STATS_LABEL_FONT_SIZE);
    int min_latency_column_width = MeasureText("Min latency", STATS_LABEL_FONT_SIZE);
    int max_latency_column_width = MeasureText("Max latency", STATS_LABEL_FONT_SIZE);
    int avg_latency_column_width = MeasureText("Avg latency", STATS_LABEL_FONT_SIZE);
    int min_preempts_column_width = MeasureText("Min preempts", STATS_LABEL_FONT_SIZE);
    int max_preempts_column_width = MeasureText("Max preempts", STATS_LABEL_FONT_SIZE);
    int avg_preempts_column_width = MeasureText("Avg preempts", STATS_LABEL_FONT_SIZE);
    for (size_t i = 0; i < cgroups.length; i++) {
        Cgroup cgroup = cgroups.data[i];
        if (!cgroup.is_visible || !cgroup.is_enabled) continue;

        snprintf(buffer, BUFFER_SIZE, "%lu", cgroup.id);
        id_column_width = MAX(id_column_width, MeasureText(buffer, STATS_DATA_FONT_SIZE));

        snprintf(buffer, BUFFER_SIZE, "%s", get_cgroup_name(cgroup_names, cgroup.id));
        name_column_width = MAX(name_column_width, MeasureText(buffer, STATS_DATA_FONT_SIZE));

        snprintf(buffer, BUFFER_SIZE, "%ums", cgroup.min_latency_ms);
        min_latency_column_width = MAX(min_latency_column_width, MeasureText(buffer, STATS_DATA_FONT_SIZE));

        snprintf(buffer, BUFFER_SIZE, "%ums", cgroup.max_latency_ms);
        max_latency_column_width = MAX(max_latency_column_width, MeasureText(buffer, STATS_DATA_FONT_SIZE));

        snprintf(buffer, BUFFER_SIZE, "%ums", (unsigned int) cgroup.total_latency_ms / cgroup.latency_count);
        avg_latency_column_width = MAX(avg_latency_column_width, MeasureText(buffer, STATS_DATA_FONT_SIZE));

        snprintf(buffer, BUFFER_SIZE, "%u", cgroup.min_preempts);
        min_preempts_column_width = MAX(min_preempts_column_width, MeasureText(buffer, STATS_DATA_FONT_SIZE));

        snprintf(buffer, BUFFER_SIZE, "%u", cgroup.max_preempts);
        max_preempts_column_width = MAX(max_preempts_column_width, MeasureText(buffer, STATS_DATA_FONT_SIZE));

        if (cgroup.preempts_count > 0) {
            snprintf(buffer, BUFFER_SIZE, "%u", (unsigned int) cgroup.total_preempts / cgroup.preempts_count);
        } else {
            snprintf(buffer, BUFFER_SIZE, "null");
        }
        avg_preempts_column_width = MAX(avg_preempts_column_width, MeasureText(buffer, STATS_DATA_FONT_SIZE));
    }

    int id_column_x = HOR_PADDING;
    int name_column_x = id_column_x + id_column_width + STATS_COLUMN_PADDING;
    int min_latency_column_x = name_column_x + name_column_width + STATS_COLUMN_PADDING;
    int max_latency_column_x = min_latency_column_x + min_latency_column_width + STATS_COLUMN_PADDING;
    int avg_latency_column_x = max_latency_column_x + max_latency_column_width + STATS_COLUMN_PADDING;
    int min_preempts_column_x = avg_latency_column_x + avg_latency_column_width + STATS_COLUMN_PADDING;
    int max_preempts_column_x = min_preempts_column_x + min_preempts_column_width + STATS_COLUMN_PADDING;
    int avg_preempts_column_x = max_preempts_column_x + max_preempts_column_width + STATS_COLUMN_PADDING;

    int y = start_y;
    DrawText("Id", id_column_x, y, STATS_LABEL_FONT_SIZE, FOREGROUND);
    DrawText("Name", name_column_x, y, STATS_LABEL_FONT_SIZE, FOREGROUND);
    DrawText("Min latency", min_latency_column_x, y, STATS_LABEL_FONT_SIZE, FOREGROUND);
    DrawText("Max latency", max_latency_column_x, y, STATS_LABEL_FONT_SIZE, FOREGROUND);
    DrawText("Avg latency", avg_latency_column_x, y, STATS_LABEL_FONT_SIZE, FOREGROUND);
    DrawText("Min preempts", min_preempts_column_x, y, STATS_LABEL_FONT_SIZE, FOREGROUND);
    DrawText("Max preempts", max_preempts_column_x, y, STATS_LABEL_FONT_SIZE, FOREGROUND);
    DrawText("Avg preempts", avg_preempts_column_x, y, STATS_LABEL_FONT_SIZE, FOREGROUND);
    y += id_column_dim.y + TEXT_MARGIN;

    for (size_t i = 0; i < cgroups.length; i++) {
        Cgroup cgroup = cgroups.data[i];
        if (!cgroup.is_visible || !cgroup.is_enabled) continue;

        snprintf(buffer, BUFFER_SIZE, "%lu", cgroup.id);
        Vector2 td = MeasureText2(buffer, STATS_DATA_FONT_SIZE);
        DrawText(buffer, id_column_x, y, STATS_DATA_FONT_SIZE, cgroup.color);

        snprintf(buffer, BUFFER_SIZE, "%s", get_cgroup_name(cgroup_names, cgroup.id));
        DrawText(buffer, name_column_x, y, STATS_DATA_FONT_SIZE, FOREGROUND);

        snprintf(buffer, BUFFER_SIZE, "%ums", cgroup.min_latency_ms);
        DrawText(buffer, min_latency_column_x, y, STATS_DATA_FONT_SIZE, FOREGROUND);

        snprintf(buffer, BUFFER_SIZE, "%ums", cgroup.max_latency_ms);
        DrawText(buffer, max_latency_column_x, y, STATS_DATA_FONT_SIZE, FOREGROUND);

        snprintf(buffer, BUFFER_SIZE, "%ums", (unsigned int) cgroup.total_latency_ms / cgroup.latency_count);
        DrawText(buffer, avg_latency_column_x, y, STATS_DATA_FONT_SIZE, FOREGROUND);

        snprintf(buffer, BUFFER_SIZE, "%u", cgroup.min_preempts);
        DrawText(buffer, min_preempts_column_x, y, STATS_DATA_FONT_SIZE, FOREGROUND);

        snprintf(buffer, BUFFER_SIZE, "%u", cgroup.max_preempts);
        DrawText(buffer, max_preempts_column_x, y, STATS_DATA_FONT_SIZE, FOREGROUND);

        if (cgroup.preempts_count > 0) {
            snprintf(buffer, BUFFER_SIZE, "%u", (unsigned int) cgroup.total_preempts / cgroup.preempts_count);
        } else {
            snprintf(buffer, BUFFER_SIZE, "null");
        }
        DrawText(buffer, avg_preempts_column_x, y, STATS_DATA_FONT_SIZE, FOREGROUND);

        y += td.y + TEXT_MARGIN;
        if (y >= HEIGHT) break;
    }
}

int main(void) {
    if (RAYLIB_VERSION_MAJOR != 5) ERROR("the required raylib version is 5.");

    if (geteuid() != 0) ERROR("must be ran as root.");

    CgroupNameVec cgroup_names = {0};
    char path[PATH_BUFFER_SIZE] = "/sys/fs/cgroup/";
    collect_cgroup_names(&cgroup_names, path);

    bool is_child_running = true;
    int input_fd;
    pid_t child;
    start_ebpf(&input_fd, &child);

    double offset = 0.0f;
    double x_scale = 1.0f;
    double latency_y_scale = 0.95f;
    double preempts_y_scale = 0.95f;

    EntryVec entries = {0};
    CgroupVec cgroups = {0};

    uint32_t min_time_s = UINT32_MAX;
    uint32_t max_time_s = 0;
    uint64_t min_ts_ms = UINT64_MAX;
    uint64_t max_ts_ms = 0;
    uint32_t max_latency_ms = 0;
    uint32_t max_preempts = 0;
    double time_per_px = 0;
    double ts_per_px = 0;
    double latency_per_px = 0;
    double preempts_per_px = 0;

    bool draw_latency = true;
    bool draw_preempts = true;

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

            min_ts_ms = entries.data[0].ts_ns / 1000000;
            max_ts_ms = entries.data[entries.length - 1].ts_ns / 1000000;
            ts_per_px = (max_ts_ms - min_ts_ms) / ((double) INNER_WIDTH);

            min_time_s = entries.data[0].time_s;
            max_time_s = entries.data[entries.length - 1].time_s;
            time_per_px = (max_time_s - min_time_s) / ((double) INNER_WIDTH);

            // Updates max values
            group_entries(&max_latency_ms, &max_preempts, &cgroups, entries);

            // Min latency and preemptions are assumed to be 0
            latency_per_px = max_latency_ms / ((double) INNER_HEIGHT);
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

        if (IsKeyPressed(KEY_Z)) draw_latency = !draw_latency;
        if (IsKeyPressed(KEY_X)) draw_preempts = !draw_preempts;

        // Drawing

        BeginDrawing();
        ClearBackground(BACKGROUND);
        SetMouseCursor(MOUSE_CURSOR_DEFAULT);

        int x_axis_max_y
            = draw_x_axis(offset, x_scale, min_time_s, max_time_s, min_ts_ms, max_ts_ms, time_per_px, ts_per_px);
        draw_y_axis(latency_y_scale, latency_per_px, preempts_y_scale, preempts_per_px);
        draw_legend(cgroups);
        draw_graph(draw_latency, draw_preempts, cgroups, offset, x_scale, latency_y_scale, preempts_y_scale, min_ts_ms,
                   max_ts_ms, ts_per_px, latency_per_px, preempts_per_px);  // collects stats
        draw_stats(x_axis_max_y, cgroups, cgroup_names);

        EndDrawing();
    }

    CloseWindow();

    for (size_t i = 0; i < cgroups.length; i++) {
        VECTOR_FREE(&cgroups.data[i].latencies);
        VECTOR_FREE(&cgroups.data[i].preempts);
    }
    VECTOR_FREE(&cgroups);
    VECTOR_FREE(&entries);
    for (size_t i = 0; i < cgroup_names.length; i++) free(cgroup_names.data[i].name);
    VECTOR_FREE(&cgroup_names);

    kill(child, SIGTERM);
    close(input_fd);

    return EXIT_SUCCESS;
}
