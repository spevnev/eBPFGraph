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
#include <time.h>
#include <unistd.h>

// Window
static const char *TITLE = "eBPF Graph";
static const int MIN_WIDTH = 800;
static const int MIN_HEIGHT = 500;
static const int DEFAULT_WIDTH = 1600;
static const int DEFAULT_HEIGHT = 1000;

// Graph
static const int HOR_PADDING = 60;
static const int TOP_PADDING = 75;
static const float BOT_PADDING_PERCENT = 0.34f;  // The rest is graph
static const int GRID_SIZE = 100;

// Units
static const int NS_IN_US = 1000;
static const int NS_IN_MS = 1000000;
static const int KTIME_SCALING = 1000000;  // ns -> ms

// Axes
static const int AXIS_LABEL_FONT_SIZE = 14;
static const int AXIS_DATA_FONT_SIZE = 10;
static const int TEXT_MARGIN = 6;

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
static const uint64_t CGROUP_BATCHING_TIME_NS = 1000000000;    // 1s
static const uint64_t CGROUP_ZERO_POINT_TIME_NS = 1000000000;  // 1s

// Controls
static const float OFFSET_SPEED = 20.0f;
static const float X_SCALE_SPEED = 1.07f;
static const float Y_SCALE_SPEED = 1.07f;
static const float MIN_Y_SCALE = 0.75f;
static const int MIN_NUMBER_OF_POINTS_VISIBLE = 4;

// Cgroup path
static const int CGROUP_PATH_PREFIX_LENGTH = 14;  // = strlen("/sys/fs/cgroup");
#define PATH_BUFFER_SIZE 4096
static const char *SYSTEMD_CGROUP_NAMES[] = {"system.slice", "session.slice", "app.slice", "init.scope"};

// Global buffer for temp snprintf-ing
#define BUFFER_SIZE 256
static char buffer[BUFFER_SIZE];

// Global variables
static int width, height, graph_width, graph_height, bot_padding;
static double x_offset = 0.0f;
static double x_scale = 1.0f;
static double latency_y_scale = 0.95f;
static double preempts_y_scale = 0.95f;
static uint32_t min_time_s = UINT32_MAX;
static uint32_t max_time_s = 0;
static double time_per_px = 0;
static uint64_t min_ktime_ns = UINT64_MAX;
static uint64_t max_ktime_ns = 0;
static double ktime_per_px = 0;
static uint64_t max_latency_ns = 0;
static double latency_per_px = 0;
static uint32_t max_preempts = 0;
static double preempts_per_px = 0;
static bool draw_latency = true;
static bool draw_preempts = true;
static bool bar_graph = true;

#define ERROR(...)                    \
    do {                              \
        fprintf(stderr, "ERROR: ");   \
        fprintf(stderr, __VA_ARGS__); \
        fprintf(stderr, "\n");        \
        exit(EXIT_FAILURE);           \
    } while (0)

#define temp_snprintf(...)                                            \
    do {                                                              \
        int chars = snprintf(buffer, BUFFER_SIZE, __VA_ARGS__);       \
        if (chars >= BUFFER_SIZE) ERROR("temp buffer is too small."); \
    } while (0)

#define INITIAL_VECTOR_CAPACITY 16

#define VECTOR_TYPEDEF(name, type) \
    typedef struct {               \
        int capacity;              \
        int length;                \
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
    bool is_systemd;
} CgroupInfo;

VECTOR_TYPEDEF(CgroupInfoVec, CgroupInfo);

typedef struct {
    uint8_t did_preempt;
    uint32_t time_s;
    uint64_t ktime_ns;
    uint64_t cgroup_id;
    uint64_t latency_ns;
} Entry;

VECTOR_TYPEDEF(EntryVec, Entry);

typedef struct {
    uint64_t ktime_ns;
    uint64_t total_latency_ns;
    uint32_t count;
} Latency;

VECTOR_TYPEDEF(LatencyVec, Latency);

typedef struct {
    uint64_t ktime_ns;
    uint32_t count;
} Preempt;

VECTOR_TYPEDEF(PreemptVec, Preempt);

typedef struct {
    bool is_enabled;

    bool is_systemd;
    uint64_t id;
    Color color;

    uint32_t entries_count;

    LatencyVec latencies;
    uint64_t min_latency_ns;
    uint64_t max_latency_ns;
    uint64_t total_latency_ns;
    uint32_t latency_count;

    PreemptVec preempts;
    uint32_t min_preempts;
    uint32_t max_preempts;
    uint64_t total_preempts;
    uint32_t preempts_count;
} Cgroup;

VECTOR_TYPEDEF(CgroupVec, Cgroup);

#define MeasureText2(text, font_size) \
    MeasureTextEx(GetFontDefault(), (text), (font_size), (font_size) / GetFontDefault().baseSize)

#define MAX(a, b) ((a) >= (b) ? (a) : (b))
#define MIN(a, b) ((a) <= (b) ? (a) : (b))

static void collect_cgroup_names_rec(CgroupInfoVec *cgroup_names, char *path, bool is_systemd) {
    struct stat stats;
    if (stat(path, &stats) == -1) ERROR("unable to stat \"%s\".", path);

    CgroupInfo cgroup = {
        .id = stats.st_ino,
        .name = strdup(path + CGROUP_PATH_PREFIX_LENGTH),
        .is_systemd = is_systemd,
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

        bool is_cgroup_systemd = is_systemd;
        for (size_t i = 0; i < sizeof(SYSTEMD_CGROUP_NAMES) / sizeof(*SYSTEMD_CGROUP_NAMES) && !is_cgroup_systemd;
             i++) {
            if (strcmp(dirent->d_name, SYSTEMD_CGROUP_NAMES[i]) == 0) is_cgroup_systemd = true;
        }
        collect_cgroup_names_rec(cgroup_names, path, is_cgroup_systemd);
    }
    closedir(dir);
}

static void collect_cgroup_names(CgroupInfoVec *cgroup_names) {
    cgroup_names->length = 0;
    char path[PATH_BUFFER_SIZE] = "/sys/fs/cgroup/";
    collect_cgroup_names_rec(cgroup_names, path, false);
}

static const char *get_cgroup_name(CgroupInfoVec *cgroup_names, uint64_t id) {
    if (id == UINT64_MAX) return "systemd services";

    bool can_retry = true;
retry:
    for (int i = 0; i < cgroup_names->length; i++) {
        if (cgroup_names->data[i].id == id) return cgroup_names->data[i].name;
    }

    if (!can_retry) ERROR("unable to map cgroup id to name/path.");
    can_retry = false;

    collect_cgroup_names(cgroup_names);
    goto retry;
}

static bool is_cgroup_systemd(CgroupInfoVec *cgroup_names, uint64_t id) {
    bool can_retry = true;
retry:
    for (int i = 0; i < cgroup_names->length; i++) {
        if (cgroup_names->data[i].id == id) return cgroup_names->data[i].is_systemd;
    }

    if (!can_retry) ERROR("unable to map cgroup id to name/path.");
    can_retry = false;

    collect_cgroup_names(cgroup_names);
    goto retry;
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
            uint64_t did_preempt;
            ch = u64_field(&did_preempt, ch);
            assert(did_preempt <= UINT8_MAX);
            entry.did_preempt = did_preempt;
            ch = u64_field(&entry.cgroup_id, ch);
            ch = u64_field(&entry.latency_ns, ch);
            ch = u64_field(&entry.ktime_ns, ch);
            assert(*ch == '\n');

            VECTOR_PUSH(entries, entry);
        }
    }
    if (bytes == -1 && errno != EAGAIN) ERROR("unable to read from eBPF process.");
    if (bytes == 0) return -1;

    return 0;
}

static Cgroup *get_or_create_cgroup(CgroupVec *cgroups, CgroupInfoVec *cgroup_names, uint64_t id) {
    if (is_cgroup_systemd(cgroup_names, id)) {
        static int idx = -1;

        if (idx == -1) {
            Cgroup new_cgroup = {
                .is_enabled = true,
                .is_systemd = true,
                .id = UINT64_MAX,
                .color = COLORS[cgroups->length % COLORS_LEN],
                .entries_count = 0,
                .latencies = {0},
                .preempts = {0},
            };

            VECTOR_PUSH(cgroups, new_cgroup);
            idx = cgroups->length - 1;
        }

        return &cgroups->data[idx];
    }

    for (int i = 0; i < cgroups->length; i++) {
        if (cgroups->data[i].id == id) return &cgroups->data[i];
    }

    Cgroup new_cgroup = {
        .is_enabled = true,
        .is_systemd = false,
        .id = id,
        .color = COLORS[cgroups->length % COLORS_LEN],
        .entries_count = 0,
        .latencies = {0},
        .preempts = {0},
    };

    VECTOR_PUSH(cgroups, new_cgroup);
    return &cgroups->data[cgroups->length - 1];
}

static void group_entries(CgroupVec *cgroups, CgroupInfoVec *cgroup_names, EntryVec *entries) {
    assert(cgroups != NULL);

    for (int i = 0; i < entries->length; i++) {
        Entry entry = entries->data[i];

        Cgroup *cgroup = get_or_create_cgroup(cgroups, cgroup_names, entry.cgroup_id);
        Latency *last_latency = VECTOR_LAST(&cgroup->latencies);
        if (last_latency != NULL && entry.ktime_ns - last_latency->ktime_ns < CGROUP_BATCHING_TIME_NS) {
            last_latency->total_latency_ns += entry.latency_ns;
            last_latency->count++;
        } else {
            if (last_latency != NULL && last_latency->count > 0) {
                max_ktime_ns = MAX(max_ktime_ns, last_latency->ktime_ns);
                max_latency_ns = MAX(max_latency_ns, last_latency->total_latency_ns / last_latency->count);
            }

            Latency latency = {
                .ktime_ns = entry.ktime_ns,
                .total_latency_ns = entry.latency_ns,
                .count = 1,
            };
            VECTOR_PUSH(&cgroup->latencies, latency);
        }
        cgroup->entries_count++;

        if (!entry.did_preempt) continue;

        Preempt *last_preempt = VECTOR_LAST(&cgroup->preempts);
        if (last_preempt != NULL && entry.ktime_ns - last_preempt->ktime_ns < CGROUP_BATCHING_TIME_NS) {
            last_preempt->count++;
        } else {
            if (last_preempt != NULL) {
                max_ktime_ns = MAX(max_ktime_ns, last_preempt->ktime_ns);
                max_preempts = MAX(max_preempts, last_preempt->count);
            }

            Preempt preempt = {
                .ktime_ns = entry.ktime_ns,
                .count = 1,
            };
            VECTOR_PUSH(&cgroup->preempts, preempt);
        }
    }
    entries->length = 0;

    for (int i = 0; i < cgroups->length; i++) {
        Cgroup *cgroup = &cgroups->data[i];

        Latency *last_latency = VECTOR_LAST(&cgroup->latencies);
        if (last_latency != NULL && last_latency->count > 0 && last_latency->ktime_ns < max_ktime_ns
            && max_ktime_ns - last_latency->ktime_ns > CGROUP_ZERO_POINT_TIME_NS) {
            max_latency_ns = MAX(max_latency_ns, last_latency->total_latency_ns / last_latency->count);

            Latency latency = {
                .ktime_ns = max_ktime_ns,
                .total_latency_ns = 0,
                .count = 0,
            };
            VECTOR_PUSH(&cgroup->latencies, latency);
        }

        Preempt *last_preempt = VECTOR_LAST(&cgroup->preempts);
        if (last_preempt != NULL && last_preempt->count > 0 && last_preempt->ktime_ns < max_ktime_ns
            && max_ktime_ns - last_preempt->ktime_ns > CGROUP_ZERO_POINT_TIME_NS) {
            max_preempts = MAX(max_preempts, last_preempt->count);

            Preempt preempt = {
                .ktime_ns = max_ktime_ns,
                .count = 0,
            };
            VECTOR_PUSH(&cgroup->preempts, preempt);
        }
    }
}

static void temp_print_scaled_latency(uint64_t latency_ns) {
    if (latency_ns >= NS_IN_MS) {
        temp_snprintf("%lums", latency_ns / NS_IN_MS);
    } else {
        temp_snprintf("%luus", latency_ns / NS_IN_US);
    }
}

static int draw_x_axis() {
    int max_y = 0;
    for (int i = 0; i <= graph_width / GRID_SIZE; i++) {
        int x = i * GRID_SIZE + HOR_PADDING;
        int y = height - bot_padding + TEXT_MARGIN;

        DrawLine(x, TOP_PADDING, x, height - bot_padding, GRID_COLOR);

        uint64_t ktime_ns
            = min_ktime_ns + ktime_per_px * i * GRID_SIZE / x_scale + (max_ktime_ns - min_ktime_ns) * x_offset;
        temp_snprintf("%lu", ktime_ns / KTIME_SCALING);
        Vector2 td = MeasureText2(buffer, AXIS_DATA_FONT_SIZE);
        DrawText(buffer, x - td.x / 2, y, AXIS_DATA_FONT_SIZE, FOREGROUND);
        y += td.y + TEXT_MARGIN;

        int time_s = min_time_s + time_per_px * i * GRID_SIZE / x_scale + (max_time_s - min_time_s) * x_offset;
        temp_snprintf("%d:%02d:%02d", (time_s / 3600) % 24, (time_s / 60) % 60, time_s % 60);
        td = MeasureText2(buffer, AXIS_DATA_FONT_SIZE);
        DrawText(buffer, x - td.x / 2, y, AXIS_DATA_FONT_SIZE, FOREGROUND);
        y += td.y + TEXT_MARGIN;

        max_y = MAX(max_y, y);
    }

    return max_y;
}

static void draw_y_axis() {
    Vector2 td = MeasureText2("Latency", AXIS_LABEL_FONT_SIZE);
    DrawText("Latency", HOR_PADDING - td.x / 2, TOP_PADDING - td.y - TEXT_MARGIN, AXIS_LABEL_FONT_SIZE, FOREGROUND);

    td = MeasureText2("Preemptions", AXIS_LABEL_FONT_SIZE);
    DrawText("Preemptions", width - HOR_PADDING - td.x / 2, TOP_PADDING - td.y - TEXT_MARGIN, AXIS_LABEL_FONT_SIZE,
             FOREGROUND);

    for (int i = 0; i <= graph_height / GRID_SIZE; i++) {
        int y = height - bot_padding - GRID_SIZE * i;
        DrawLine(HOR_PADDING, y, width - HOR_PADDING, y, GRID_COLOR);

        uint64_t latency_ns = latency_per_px * i * GRID_SIZE / latency_y_scale;
        temp_print_scaled_latency(latency_ns);
        td = MeasureText2(buffer, AXIS_DATA_FONT_SIZE);
        DrawText(buffer, HOR_PADDING - td.x - TEXT_MARGIN, y - td.y / 2, AXIS_DATA_FONT_SIZE, FOREGROUND);

        uint32_t preempts = preempts_per_px * i * GRID_SIZE / preempts_y_scale;
        temp_snprintf("%u", preempts);
        td = MeasureText2(buffer, AXIS_DATA_FONT_SIZE);
        DrawText(buffer, width - HOR_PADDING + TEXT_MARGIN, y - td.y / 2, AXIS_DATA_FONT_SIZE, FOREGROUND);
    }
}

static void draw_legend(CgroupVec cgroups) {
    int x = HOR_PADDING;
    for (int i = 0; i < cgroups.length; i++) {
        Cgroup *cgroup = &cgroups.data[i];

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
                    for (int j = 0; j < cgroups.length; j++) cgroups.data[j].is_enabled = false;
                    cgroup->is_enabled = true;
                } else {
                    cgroup->is_enabled = !cgroup->is_enabled;
                }
            }
        }

        if (cgroup->is_systemd) temp_snprintf("systemd services");
        else temp_snprintf("%lu", cgroup->id);

        Vector2 td = MeasureText2(buffer, LEGEND_FONT_SIZE);
        DrawText(buffer, x, LEGEND_TOP_MARGIN - td.y / 2, LEGEND_FONT_SIZE, cgroup->color);
        x += td.x + LEGEND_PADDING;
    }
}

static void draw_graph_line(double px, double py, double x, double y, Color color) {
    if (bar_graph) {
        double rpx = HOR_PADDING + MAX(px, 0);
        double rx = MIN(HOR_PADDING + x, width - HOR_PADDING);
        double rpy = height - bot_padding - MIN(py, graph_height);
        double ry = height - bot_padding - MIN(y, graph_height);

        if (py <= graph_height) DrawLine(rpx, rpy, rx, rpy, color);
        if (x <= graph_width) DrawLine(rx, rpy, rx, ry, color);
    } else {
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
        if (rx > graph_width) {
            assert(x != px);
            double k = (x - graph_width) / ((double) (x - px));
            rx = graph_width;
            ry = py + (y - py) * (1.0f - k);
        }
        if (rpy > graph_height && y != py) {
            double k = (py - graph_height) / ((double) (py - y));
            rpx = px + (x - px) * k;
            rpy = graph_height;
        }
        if (ry > graph_height) {
            assert(y != py);
            double k = (y - graph_height) / ((double) (y - py));
            rx = px + (x - px) * (1.0f - k);
            ry = graph_height;
        }

        DrawLine(HOR_PADDING + rpx, height - bot_padding - rpy, HOR_PADDING + rx, height - bot_padding - ry, color);
    }
}

static void draw_graph(CgroupVec cgroups) {
    for (int i = 0; i < cgroups.length; i++) {
        Cgroup *cgroup = &cgroups.data[i];
        if (!cgroup->is_enabled) continue;

        if (draw_latency) {
            // Reset stats
            cgroup->min_latency_ns = UINT64_MAX;
            cgroup->max_latency_ns = 0;
            cgroup->total_latency_ns = 0;
            cgroup->latency_count = 0;

            double px = -1;
            double py = -1;
            double npx = -1;
            double npy = -1;
            for (int j = 0; j < cgroup->latencies.length; j++, px = npx, py = npy) {
                Latency point = cgroup->latencies.data[j];
                double latency = point.count > 0 ? point.total_latency_ns / ((double) point.count) : 0;

                double x = (point.ktime_ns - min_ktime_ns - (max_ktime_ns - min_ktime_ns) * x_offset) / ktime_per_px
                           * x_scale;
                double y = latency / latency_per_px * latency_y_scale;

                npx = x;
                npy = y;

                if (x < 0) continue;
                if (x > graph_width && px > graph_width) break;
                if (px > x) continue;

                cgroup->min_latency_ns = MIN(cgroup->min_latency_ns, latency);
                cgroup->max_latency_ns = MAX(cgroup->max_latency_ns, latency);
                cgroup->total_latency_ns += latency;
                cgroup->latency_count++;

                if (y > graph_height && py > graph_height) continue;
                if (px == -1) continue;

                draw_graph_line(px, py, x, y, cgroup->color);
            }
            if (px > 0 && px < graph_width) draw_graph_line(px, py, graph_width, py, cgroup->color);
        }

        if (draw_preempts) {
            // Reset stats
            cgroup->min_preempts = UINT32_MAX;
            cgroup->max_preempts = 0;
            cgroup->total_preempts = 0;
            cgroup->preempts_count = 0;

            Vector3 hsv = ColorToHSV(cgroup->color);
            Color preempt_color = ColorFromHSV(hsv.x, hsv.y * 0.5f, hsv.z * 0.5f);

            double px = -1;
            double py = -1;
            double npx = -1;
            double npy = -1;
            for (int j = 0; j < cgroup->preempts.length; j++, px = npx, py = npy) {
                Preempt point = cgroup->preempts.data[j];

                double x = (point.ktime_ns - min_ktime_ns - (max_ktime_ns - min_ktime_ns) * x_offset) / ktime_per_px
                           * x_scale;
                double y = point.count / preempts_per_px * preempts_y_scale;

                npx = x;
                npy = y;

                if (x < 0) continue;
                if (x > graph_width && px > graph_width) break;
                if (px > x) continue;

                cgroup->min_preempts = MIN(cgroup->min_preempts, point.count);
                cgroup->max_preempts = MAX(cgroup->max_preempts, point.count);
                cgroup->total_preempts += point.count;
                cgroup->preempts_count++;

                if (y > graph_height && py > graph_width) continue;
                if (px == -1) continue;

                draw_graph_line(px, py, x, y, preempt_color);
            }
            if (px > 0 && px < graph_width) draw_graph_line(px, py, graph_width, py, preempt_color);
        }
    }
}

static void draw_stats(int start_y, CgroupVec cgroups, CgroupInfoVec *cgroup_names) {
    Vector2 id_column_dim = MeasureText2("Id", STATS_LABEL_FONT_SIZE);
    int id_column_width = id_column_dim.x;
    int name_column_width = MeasureText("Name", STATS_LABEL_FONT_SIZE);
    int min_latency_column_width = MeasureText("Min latency", STATS_LABEL_FONT_SIZE);
    int max_latency_column_width = MeasureText("Max latency", STATS_LABEL_FONT_SIZE);
    int avg_latency_column_width = MeasureText("Avg latency", STATS_LABEL_FONT_SIZE);
    int min_preempts_column_width = MeasureText("Min preempts", STATS_LABEL_FONT_SIZE);
    int max_preempts_column_width = MeasureText("Max preempts", STATS_LABEL_FONT_SIZE);
    int avg_preempts_column_width = MeasureText("Avg preempts", STATS_LABEL_FONT_SIZE);
    for (int i = 0; i < cgroups.length; i++) {
        Cgroup cgroup = cgroups.data[i];
        if (!cgroup.is_enabled) continue;

        if (!cgroup.is_systemd) {
            temp_snprintf("%lu", cgroup.id);
        } else {
            temp_snprintf("null");
        }
        id_column_width = MAX(id_column_width, MeasureText(buffer, STATS_DATA_FONT_SIZE));

        temp_snprintf("%s", get_cgroup_name(cgroup_names, cgroup.id));
        name_column_width = MAX(name_column_width, MeasureText(buffer, STATS_DATA_FONT_SIZE));

        if (cgroup.latency_count > 0) {
            temp_print_scaled_latency(cgroup.min_latency_ns);
            min_latency_column_width = MAX(min_latency_column_width, MeasureText(buffer, STATS_DATA_FONT_SIZE));

            temp_print_scaled_latency(cgroup.max_latency_ns);
            max_latency_column_width = MAX(max_latency_column_width, MeasureText(buffer, STATS_DATA_FONT_SIZE));

            temp_print_scaled_latency(cgroup.total_latency_ns / cgroup.latency_count);
            avg_latency_column_width = MAX(avg_latency_column_width, MeasureText(buffer, STATS_DATA_FONT_SIZE));
        } else {
            temp_snprintf("null");
            min_latency_column_width = MAX(min_latency_column_width, MeasureText(buffer, STATS_DATA_FONT_SIZE));
            max_latency_column_width = MAX(max_latency_column_width, MeasureText(buffer, STATS_DATA_FONT_SIZE));
            avg_latency_column_width = MAX(avg_latency_column_width, MeasureText(buffer, STATS_DATA_FONT_SIZE));
        }

        if (cgroup.preempts_count > 0) {
            temp_snprintf("%u", cgroup.min_preempts);
            min_preempts_column_width = MAX(min_preempts_column_width, MeasureText(buffer, STATS_DATA_FONT_SIZE));

            temp_snprintf("%u", cgroup.max_preempts);
            max_preempts_column_width = MAX(max_preempts_column_width, MeasureText(buffer, STATS_DATA_FONT_SIZE));

            temp_snprintf("%lu", cgroup.total_preempts / cgroup.preempts_count);
            avg_preempts_column_width = MAX(avg_preempts_column_width, MeasureText(buffer, STATS_DATA_FONT_SIZE));
        } else {
            temp_snprintf("null");
            min_preempts_column_width = MAX(min_preempts_column_width, MeasureText(buffer, STATS_DATA_FONT_SIZE));
            max_preempts_column_width = MAX(max_preempts_column_width, MeasureText(buffer, STATS_DATA_FONT_SIZE));
            avg_preempts_column_width = MAX(avg_preempts_column_width, MeasureText(buffer, STATS_DATA_FONT_SIZE));
        }
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

    for (int i = 0; i < cgroups.length; i++) {
        Cgroup cgroup = cgroups.data[i];
        if (!cgroup.is_enabled) continue;

        if (!cgroup.is_systemd) {
            temp_snprintf("%lu", cgroup.id);
        } else {
            temp_snprintf("null");
        }
        Vector2 td = MeasureText2(buffer, STATS_DATA_FONT_SIZE);
        DrawText(buffer, id_column_x, y, STATS_DATA_FONT_SIZE, cgroup.color);

        temp_snprintf("%s", get_cgroup_name(cgroup_names, cgroup.id));
        DrawText(buffer, name_column_x, y, STATS_DATA_FONT_SIZE, FOREGROUND);

        if (cgroup.latency_count > 0) {
            temp_print_scaled_latency(cgroup.min_latency_ns);
            DrawText(buffer, min_latency_column_x, y, STATS_DATA_FONT_SIZE, FOREGROUND);

            temp_print_scaled_latency(cgroup.max_latency_ns);
            DrawText(buffer, max_latency_column_x, y, STATS_DATA_FONT_SIZE, FOREGROUND);

            temp_print_scaled_latency(cgroup.total_latency_ns / cgroup.latency_count);
            DrawText(buffer, avg_latency_column_x, y, STATS_DATA_FONT_SIZE, FOREGROUND);
        } else {
            temp_snprintf("null");
            DrawText(buffer, min_latency_column_x, y, STATS_DATA_FONT_SIZE, FOREGROUND);
            DrawText(buffer, max_latency_column_x, y, STATS_DATA_FONT_SIZE, FOREGROUND);
            DrawText(buffer, avg_latency_column_x, y, STATS_DATA_FONT_SIZE, FOREGROUND);
        }

        if (cgroup.preempts_count > 0) {
            temp_snprintf("%u", cgroup.min_preempts);
            DrawText(buffer, min_preempts_column_x, y, STATS_DATA_FONT_SIZE, FOREGROUND);

            temp_snprintf("%u", cgroup.max_preempts);
            DrawText(buffer, max_preempts_column_x, y, STATS_DATA_FONT_SIZE, FOREGROUND);

            temp_snprintf("%lu", cgroup.total_preempts / cgroup.preempts_count);
            DrawText(buffer, avg_preempts_column_x, y, STATS_DATA_FONT_SIZE, FOREGROUND);
        } else {
            temp_snprintf("null");
            DrawText(buffer, min_preempts_column_x, y, STATS_DATA_FONT_SIZE, FOREGROUND);
            DrawText(buffer, max_preempts_column_x, y, STATS_DATA_FONT_SIZE, FOREGROUND);
            DrawText(buffer, avg_preempts_column_x, y, STATS_DATA_FONT_SIZE, FOREGROUND);
        }

        y += td.y + TEXT_MARGIN;
        if (y >= height) break;
    }
}

static void draw_performance_info(bool is_ebpf_running) {
    int fps = GetFPS();
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    uint32_t time_s = (tm->tm_hour * 60 + tm->tm_min) * 60 + tm->tm_sec;
    uint32_t time_diff = time_s - max_time_s;
    if (!is_ebpf_running) time_diff = 0;

    char buffer[32];
    snprintf(buffer, 32, "%dfps\n%us behind", fps, time_diff);

    Vector2 td = MeasureText2(buffer, STATS_DATA_FONT_SIZE);
    DrawText(buffer, width - td.x - TEXT_MARGIN, height - td.y - TEXT_MARGIN, STATS_DATA_FONT_SIZE, FOREGROUND);
}

int main(void) {
    if (RAYLIB_VERSION_MAJOR != 5) ERROR("the required raylib version is 5.");
    if (geteuid() != 0) ERROR("must be ran as root.");

    bool is_child_running = true;
    int input_fd;
    pid_t child;
    start_ebpf(&input_fd, &child);

    CgroupInfoVec cgroup_names = {0};
    collect_cgroup_names(&cgroup_names);

    EntryVec entries = {0};
    CgroupVec cgroups = {0};

    bool is_size_init = false;
    bool is_min_set = false;

    SetTraceLogLevel(LOG_WARNING);
    SetConfigFlags(FLAG_WINDOW_RESIZABLE);
    InitWindow(DEFAULT_WIDTH, DEFAULT_HEIGHT, TITLE);
    SetWindowMinSize(MIN_WIDTH, MIN_HEIGHT);
    SetTargetFPS(30);

    while (!WindowShouldClose()) {
        if (!is_size_init || IsWindowResized()) {
            is_size_init = true;

            width = GetScreenWidth();
            height = GetScreenHeight();

            graph_width = width - 2 * HOR_PADDING;
            graph_height = (height - TOP_PADDING) * (1.0f - BOT_PADDING_PERCENT);
            bot_padding = (height - TOP_PADDING) * BOT_PADDING_PERCENT;
        }

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

            if (!is_min_set) {
                is_min_set = true;
                min_ktime_ns = entries.data[0].ktime_ns;
                min_time_s = entries.data[0].time_s;
                // Min latency and preemptions are assumed to be 0
            }

            max_time_s = entries.data[entries.length - 1].time_s;

            // Updates max ktime, latency, preempts
            group_entries(&cgroups, &cgroup_names, &entries);
        }

        ktime_per_px = (max_ktime_ns - min_ktime_ns) / ((double) graph_width);
        time_per_px = (max_time_s - min_time_s) / ((double) graph_width);
        latency_per_px = max_latency_ns / ((double) graph_height);
        preempts_per_px = max_preempts / ((double) graph_height);

        // Controls

        if (IsKeyDown(KEY_LEFT)) x_offset = MAX(x_offset - 1.0f / (x_scale * OFFSET_SPEED), 0.0f);
        if (IsKeyDown(KEY_RIGHT)) x_offset = MIN(x_offset + 1.0f / (x_scale * OFFSET_SPEED), 1.0f - 1.0f / x_scale);

        if (IsKeyDown(KEY_EQUAL)) {
            x_scale = MIN(
                x_scale * X_SCALE_SPEED,
                (max_ktime_ns - min_ktime_ns) / ((double) (MIN_NUMBER_OF_POINTS_VISIBLE * CGROUP_BATCHING_TIME_NS)));
        }
        if (IsKeyDown(KEY_MINUS)) {
            x_scale = MAX(x_scale / X_SCALE_SPEED, 1.0f);
            x_offset = MIN(x_offset, 1.0f - 1.0f / x_scale);
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

        if (IsKeyPressed(KEY_F)) bar_graph = !bar_graph;

        // Drawing

        BeginDrawing();

        ClearBackground(BACKGROUND);
        SetMouseCursor(MOUSE_CURSOR_DEFAULT);

        int x_axis_max_y = draw_x_axis();
        draw_y_axis();
        draw_legend(cgroups);
        draw_graph(cgroups);  // collects stats
        draw_stats(x_axis_max_y, cgroups, &cgroup_names);
        draw_performance_info(is_child_running);

        EndDrawing();
    }

    CloseWindow();

    for (int i = 0; i < cgroups.length; i++) {
        VECTOR_FREE(&cgroups.data[i].latencies);
        VECTOR_FREE(&cgroups.data[i].preempts);
    }
    VECTOR_FREE(&cgroups);
    VECTOR_FREE(&entries);
    for (int i = 0; i < cgroup_names.length; i++) free(cgroup_names.data[i].name);
    VECTOR_FREE(&cgroup_names);

    kill(child, SIGTERM);
    close(input_fd);

    return EXIT_SUCCESS;
}
