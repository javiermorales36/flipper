#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <furi.h>
#include <furi_hal.h>
#include <gui/gui.h>
#include <gui/view.h>
#include <gui/view_dispatcher.h>
#include <gui/elements.h>
#include <gui/modules/widget.h>
#include <gui/modules/number_input.h>
#include <gui/modules/text_input.h>
#include <dialogs/dialogs.h>
#include <storage/storage.h>

#define BASIC_PI 3.1415927f

#define MAX_SOURCE_LINES  128
#define MAX_LINE_LENGTH   128
#define MAX_OUTPUT_LINES  12
#define MAX_VARIABLES     26
#define MAX_STRING_LENGTH 64
#define MAX_PLOT_POINTS   1024
#define MAX_CALL_STACK    32
#define MAX_FOR_STACK     16
#define DEFAULT_PROGRAM_PATH "/ext/basic/program.bas"
#define PROGRAM_BUFFER_SIZE  4096
#define OUTPUT_BUFFER_SIZE   1536
#define MAX_EXEC_STEPS       65536
#define STEPS_PER_TICK       4096
#define EXECUTION_VISIBLE_LINES_WITH_PLOT 1
#define EXECUTION_VISIBLE_LINES_TEXT_ONLY 4
#define MAX_EDITOR_LINES     64
#define MAX_EDITOR_LINE_LEN  32

typedef enum {
    BasicCustomEventOpenBrowser = 0,
    BasicCustomEventRunProgram,
    BasicCustomEventBackToMain,
    BasicCustomEventExit,
    BasicCustomEventInputReady,
    BasicCustomEventInputCancelled,
    BasicCustomEventTick,
    BasicCustomEventEditorEditDone,
    BasicCustomEventEditorRun,
} BasicCustomEvent;

typedef enum {
    BasicViewMain = 0,
    BasicViewExecution,
    BasicViewNumberInput,
    BasicViewEditor,
    BasicViewTextInput,
} BasicView;

typedef struct {
    int number;
    uint16_t offset;
} BasicLine;

typedef struct {
    uint8_t x;
    uint8_t y;
} BasicPlotPoint;

typedef struct {
    int var_index;
    float end_value;
    float step_value;
    int loop_index;
} BasicForFrame;

typedef struct {
    uint8_t redraw_token;
    int output_scroll;
} BasicExecutionViewModel;

typedef struct {
    uint8_t redraw_token;
} BasicMainViewModel;

typedef struct {
    int scroll;
} BasicEditorViewModel;

typedef struct {
    BasicLine lines[MAX_SOURCE_LINES];
    int line_count;
    char* program_text;
    float vars[MAX_VARIABLES];
    char string_vars[MAX_VARIABLES][MAX_STRING_LENGTH];
    bool string_flags[MAX_VARIABLES];
    char output[MAX_OUTPUT_LINES][MAX_LINE_LENGTH];
    int output_count;
    char status[MAX_LINE_LENGTH];
    bool loaded;
    BasicPlotPoint plots[MAX_PLOT_POINTS];
    int plot_count;
    int current_index;
    int steps;
    int call_stack[MAX_CALL_STACK];
    int call_depth;
    BasicForFrame for_stack[MAX_FOR_STACK];
    int for_depth;
    bool running;
    bool waiting_for_input;
    int waiting_var;
    int pending_input;
    bool exec_paused;
    uint32_t exec_pause_until;
} BasicState;

static BasicState state;
static const char* expr_ptr;
static ViewDispatcher* view_dispatcher = NULL;
static View* main_view = NULL;
static View* execution_view = NULL;
static View* editor_view = NULL;
static NumberInput* number_input = NULL;
static TextInput* text_input_editor = NULL;
static DialogsApp* dialogs = NULL;
static FuriString* program_path = NULL;
static FuriTimer* exec_timer = NULL;

static char editor_lines[MAX_EDITOR_LINES][MAX_EDITOR_LINE_LEN];
static int editor_line_count = 0;
static int editor_cursor = 0;
static char editor_text_buf[MAX_EDITOR_LINE_LEN];

static void basic_main_view_draw_callback(Canvas* canvas, void* model);
static bool basic_main_view_input_callback(InputEvent* event, void* context);
static void basic_editor_view_draw_callback(Canvas* canvas, void* model);
static bool basic_editor_view_input_callback(InputEvent* event, void* context);
static void basic_execution_view_draw_callback(Canvas* canvas, void* model);
static bool basic_execution_view_input_callback(InputEvent* event, void* context);
static void append_output(const char* text);
static void rebuild_main_view(void);
static void rebuild_execution_widget(void);
static void rebuild_editor_view(void);
static void execute_program_slice(void);
static const char* get_line_text(int index);
static void editor_load_from_state(void);
static bool editor_save_to_state(void);

static void copy_text(char* dst, size_t dst_size, const char* src) {
    if(dst_size == 0) return;
    strncpy(dst, src, dst_size - 1);
    dst[dst_size - 1] = '\0';
}

static void trim(char* s) {
    char* start = s;
    while(*start && isspace((unsigned char)*start)) start++;
    char* dst = s;
    while(*start) *dst++ = *start++;
    *dst = '\0';
    while(dst > s && isspace((unsigned char)*(dst - 1))) dst--;
    *dst = '\0';
}

static void uppercase(char* s) {
    while(*s) {
        *s = toupper((unsigned char)*s);
        s++;
    }
}

static char* skip_spaces(char* s) {
    while(*s && isspace((unsigned char)*s)) s++;
    return s;
}

static const char* skip_spaces_const(const char* s) {
    while(*s && isspace((unsigned char)*s)) s++;
    return s;
}

static char* next_word(char* s, char** next) {
    s = skip_spaces(s);
    if(*s == '\0') {
        if(next) *next = s;
        return NULL;
    }
    char* start = s;
    while(*s && !isspace((unsigned char)*s)) s++;
    if(*s) *s++ = '\0';
    if(next) *next = s;
    return start;
}

static bool is_identifier_char(char c) {
    return isalnum((unsigned char)c) || (c == '_');
}

static bool keyword_equals(const char* s, const char* keyword) {
    while(*keyword) {
        if(toupper((unsigned char)*s) != toupper((unsigned char)*keyword)) return false;
        s++;
        keyword++;
    }
    return true;
}

static const char* find_keyword_token(const char* s, const char* keyword) {
    size_t len = strlen(keyword);
    bool in_string = false;
    int paren_depth = 0;

    for(const char* p = s; *p; p++) {
        char c = *p;
        if(c == '"') {
            in_string = !in_string;
        } else if(!in_string) {
            if(c == '(') paren_depth++;
            else if((c == ')') && (paren_depth > 0)) paren_depth--;
        }

        if(in_string || (paren_depth > 0)) continue;

        if((p == s || !is_identifier_char(p[-1])) && keyword_equals(p, keyword) &&
           !is_identifier_char(p[len])) {
            return p;
        }
    }

    return NULL;
}

static const char* find_comparison_operator(const char* s, size_t* op_len) {
    bool in_string = false;
    int paren_depth = 0;

    for(const char* p = s; *p; p++) {
        char c = *p;
        if(c == '"') {
            in_string = !in_string;
        } else if(!in_string) {
            if(c == '(') paren_depth++;
            else if((c == ')') && (paren_depth > 0)) paren_depth--;
        }

        if(in_string || (paren_depth > 0)) continue;

        if((c == '<') && (p[1] == '>')) {
            *op_len = 2;
            return p;
        }
        if((c == '<') && (p[1] == '=')) {
            *op_len = 2;
            return p;
        }
        if((c == '>') && (p[1] == '=')) {
            *op_len = 2;
            return p;
        }
        if((c == '=') || (c == '<') || (c == '>')) {
            *op_len = 1;
            return p;
        }
    }

    return NULL;
}

static bool parse_line_number_token(const char* s, int* value_out) {
    s = skip_spaces_const(s);
    int value = 0;
    bool has_digits = false;

    while(isdigit((unsigned char)*s)) {
        value = value * 10 + (*s++ - '0');
        has_digits = true;
    }

    if(!has_digits) return false;
    if(*skip_spaces_const(s) != '\0') return false;
    *value_out = value;
    return true;
}

static bool parse_single_var_token(const char* s, int* var_index) {
    s = skip_spaces_const(s);
    if(!isalpha((unsigned char)*s)) return false;

    char name = toupper((unsigned char)*s++);
    if((name < 'A') || (name > 'Z')) return false;
    if(*skip_spaces_const(s) != '\0') return false;

    *var_index = name - 'A';
    return true;
}

static bool parse_quoted_string(
    const char* s,
    char* out,
    size_t out_size,
    const char** after_string) {
    s = skip_spaces_const(s);
    if(*s != '"') return false;
    s++;

    size_t index = 0;
    while(*s && (*s != '"')) {
        if(index + 1 < out_size) out[index++] = *s;
        s++;
    }

    if(*s != '"') return false;
    out[index] = '\0';
    s++;

    if(after_string) *after_string = skip_spaces_const(s);
    return true;
}

static bool is_simple_call(const char* s, const char* name) {
    s = skip_spaces_const(s);
    while(*name) {
        if(toupper((unsigned char)*s) != toupper((unsigned char)*name)) return false;
        s++;
        name++;
    }

    s = skip_spaces_const(s);
    if(*s != '(') return false;
    s = skip_spaces_const(s + 1);
    if(*s != ')') return false;
    return *skip_spaces_const(s + 1) == '\0';
}

static void set_numeric_var(int var_index, float value) {
    state.vars[var_index] = value;
    state.string_flags[var_index] = false;
    state.string_vars[var_index][0] = '\0';
}

static void set_string_var(int var_index, const char* value) {
    copy_text(state.string_vars[var_index], sizeof(state.string_vars[var_index]), value);
    state.string_flags[var_index] = true;

    char* end = NULL;
    float numeric_value = strtof(value, &end);
    state.vars[var_index] = (end != value) ? numeric_value : 0.0f;
}

static void set_getchar_var(int var_index, int input_value) {
    char text[MAX_STRING_LENGTH];
    snprintf(text, sizeof(text), "%d", input_value);
    set_string_var(var_index, text);
    state.vars[var_index] = (float)input_value;
}

static bool evaluate_string_value(const char* s, char* out, size_t out_size) {
    const char* tail = NULL;
    if(parse_quoted_string(s, out, out_size, &tail) && (*tail == '\0')) return true;

    int var_index = 0;
    if(parse_single_var_token(s, &var_index) && state.string_flags[var_index]) {
        copy_text(out, out_size, state.string_vars[var_index]);
        return true;
    }

    return false;
}

static int round_to_int(float value) {
    return (value >= 0.0f) ? (int)(value + 0.5f) : (int)(value - 0.5f);
}

static void format_number(float value, char* out, size_t out_size) {
    long rounded = (long)value;
    float delta = value - (float)rounded;
    if(delta < 0.0f) delta = -delta;

    if(delta < 0.0001f) snprintf(out, out_size, "%ld", rounded);
    else snprintf(out, out_size, "%.3f", (double)value);
}

static void clear_render_state(void) {
    state.output_count = 0;
    state.plot_count = 0;
}

static const char* get_line_text(int index) {
    if(!state.program_text) return "";
    if((index < 0) || (index >= state.line_count)) return "";
    return state.program_text + state.lines[index].offset;
}

static void append_output(const char* text) {
    if(state.output_count >= MAX_OUTPUT_LINES) {
        for(int i = 1; i < MAX_OUTPUT_LINES; i++) {
            copy_text(state.output[i - 1], sizeof(state.output[i - 1]), state.output[i]);
        }
        state.output_count = MAX_OUTPUT_LINES - 1;
    }

    copy_text(state.output[state.output_count], sizeof(state.output[state.output_count]), text);
    state.output_count++;
}

static void get_program_name(char* out, size_t out_size) {
    const char* full_path = furi_string_get_cstr(program_path);
    const char* base = strrchr(full_path, '/');
    if(base) base++;
    else base = full_path;
    copy_text(out, out_size, base);
}

static void get_execution_status_badge(char* out, size_t out_size) {
    const char* badge = "IDLE";

    if(strncmp(state.status, "Error", 5) == 0) {
        badge = "ERROR";
    } else if(state.waiting_for_input) {
        badge = "INPUT";
    } else if(state.running) {
        badge = "RUN";
    } else if(strcmp(state.status, "Programa finalizado") == 0) {
        badge = "DONE";
    } else if(state.loaded) {
        badge = "READY";
    }

    copy_text(out, out_size, badge);
}

static int get_execution_visible_lines(void) {
    return (state.plot_count > 0) ? EXECUTION_VISIBLE_LINES_WITH_PLOT :
                                    EXECUTION_VISIBLE_LINES_TEXT_ONLY;
}

static int get_execution_max_start_line(void) {
    int max_start = state.output_count - get_execution_visible_lines();
    return (max_start > 0) ? max_start : 0;
}

static void scroll_execution_to_bottom(void) {
    if(!execution_view) return;

    with_view_model(
        execution_view,
        BasicExecutionViewModel * model,
        {
            model->output_scroll = get_execution_max_start_line();
            model->redraw_token++;
        },
        true);
}

static void format_trimmed_text(const char* text, char* out, size_t out_size, size_t max_chars) {
    if(out_size == 0) return;

    char line[MAX_LINE_LENGTH];
    size_t len = strlen(text);

    if(len <= max_chars) {
        copy_text(line, sizeof(line), text);
    } else {
        if(max_chars > 3) {
            size_t prefix_len = max_chars - 3;
            if(prefix_len >= sizeof(line)) prefix_len = sizeof(line) - 1;
            memcpy(line, text, prefix_len);
            line[prefix_len] = '\0';
            snprintf(line + prefix_len, sizeof(line) - prefix_len, "...");
        } else {
            copy_text(line, sizeof(line), text);
        }
    }

    copy_text(out, out_size, line);
}

static void draw_trimmed_text(Canvas* canvas, int32_t x, int32_t y, const char* text, size_t max_chars) {
    char line[MAX_LINE_LENGTH];
    format_trimmed_text(text, line, sizeof(line), max_chars);

    canvas_draw_str(canvas, x, y, line);
}

static void draw_execution_scrollbar(
    Canvas* canvas,
    int32_t x,
    int32_t y,
    int32_t height,
    int total_lines,
    int visible_lines,
    int start_line) {
    if((total_lines <= visible_lines) || (height <= 0)) return;

    int thumb_height = (height * visible_lines) / total_lines;
    if(thumb_height < 4) thumb_height = 4;
    if(thumb_height > height) thumb_height = height;

    int track = height - thumb_height;
    int max_start = total_lines - visible_lines;
    int thumb_y = y;
    if((track > 0) && (max_start > 0)) {
        thumb_y += (track * start_line) / max_start;
    }

    canvas_draw_frame(canvas, x, y, 3, height);

    int fill_y = thumb_y + ((thumb_height > 2) ? 1 : 0);
    int fill_h = thumb_height - ((thumb_height > 2) ? 2 : 0);
    if(fill_h < 1) fill_h = 1;
    canvas_draw_box(canvas, x + 1, fill_y, 1, fill_h);
}

static void add_plot_point(float x, float y) {
    if(state.plot_count >= MAX_PLOT_POINTS) return;

    int xi = round_to_int(x);
    int yi = round_to_int(y);
    if((xi < 0) || (xi > 127) || (yi < 0) || (yi > 63)) return;

    state.plots[state.plot_count].x = (uint8_t)xi;
    state.plots[state.plot_count].y = (uint8_t)yi;
    state.plot_count++;
}

static void stop_with_runtime_error(int line_number, const char* detail) {
    snprintf(state.status, sizeof(state.status), "Error en linea %d", line_number);
    char msg[MAX_LINE_LENGTH];
    snprintf(msg, sizeof(msg), "L%d: %s", line_number, detail);
    append_output(msg);
    state.running = false;
    state.waiting_for_input = false;
}

static float parse_expression(void);

static float parse_factor(void) {
    expr_ptr = skip_spaces_const(expr_ptr);

    if(*expr_ptr == '+') {
        expr_ptr++;
        return parse_factor();
    }
    if(*expr_ptr == '-') {
        expr_ptr++;
        return -parse_factor();
    }

    if(*expr_ptr == '(') {
        expr_ptr++;
        float value = parse_expression();
        expr_ptr = skip_spaces_const(expr_ptr);
        if(*expr_ptr == ')') expr_ptr++;
        return value;
    }

    if(isalpha((unsigned char)*expr_ptr)) {
        char identifier[16];
        size_t length = 0;
        while(isalpha((unsigned char)*expr_ptr) && (length + 1 < sizeof(identifier))) {
            identifier[length++] = toupper((unsigned char)*expr_ptr++);
        }
        identifier[length] = '\0';

        expr_ptr = skip_spaces_const(expr_ptr);
        if(strcmp(identifier, "PI") == 0) return BASIC_PI;

        if(*expr_ptr == '(' &&
           (strcmp(identifier, "SIN") == 0 || strcmp(identifier, "COS") == 0 ||
            strcmp(identifier, "SQR") == 0 || strcmp(identifier, "INT") == 0 ||
            strcmp(identifier, "ABS") == 0 || strcmp(identifier, "SGN") == 0 ||
            strcmp(identifier, "TAN") == 0 || strcmp(identifier, "ATN") == 0 ||
            strcmp(identifier, "EXP") == 0 || strcmp(identifier, "LOG") == 0)) {
            expr_ptr++;
            float arg = parse_expression();
            expr_ptr = skip_spaces_const(expr_ptr);
            if(*expr_ptr == ')') expr_ptr++;
            if(strcmp(identifier, "SIN") == 0) return sinf(arg);
            if(strcmp(identifier, "COS") == 0) return cosf(arg);
            if(strcmp(identifier, "TAN") == 0) return tanf(arg);
            if(strcmp(identifier, "ATN") == 0) return atanf(arg);
            if(strcmp(identifier, "SQR") == 0) return (arg >= 0.0f) ? sqrtf(arg) : 0.0f;
            if(strcmp(identifier, "INT") == 0) return floorf(arg);
            if(strcmp(identifier, "ABS") == 0) return fabsf(arg);
            if(strcmp(identifier, "SGN") == 0) return (arg > 0.0f) ? 1.0f : (arg < 0.0f) ? -1.0f : 0.0f;
            if(strcmp(identifier, "EXP") == 0) return expf(arg);
            if(strcmp(identifier, "LOG") == 0) return (arg > 0.0f) ? logf(arg) : 0.0f;
            return 0.0f;
        }

        if(strcmp(identifier, "RND") == 0) {
            return (float)(furi_hal_random_get() & 0xFFFF) / 65535.0f;
        }

        if((length == 1) && (identifier[0] >= 'A') && (identifier[0] <= 'Z')) {
            return state.vars[identifier[0] - 'A'];
        }
    }

    char* end = NULL;
    float value = strtof(expr_ptr, &end);
    if(end != expr_ptr) {
        expr_ptr = end;
        return value;
    }

    return 0.0f;
}

static float parse_term(void) {
    float value = parse_factor();
    while(true) {
        expr_ptr = skip_spaces_const(expr_ptr);
        if((*expr_ptr == '*') || (*expr_ptr == '/')) {
            char op = *expr_ptr++;
            float rhs = parse_factor();
            if(op == '*') value *= rhs;
            else if(rhs != 0.0f) value /= rhs;
        } else {
            break;
        }
    }
    return value;
}

static float parse_expression(void) {
    float value = parse_term();
    while(true) {
        expr_ptr = skip_spaces_const(expr_ptr);
        if((*expr_ptr == '+') || (*expr_ptr == '-')) {
            char op = *expr_ptr++;
            float rhs = parse_term();
            if(op == '+') value += rhs;
            else value -= rhs;
        } else {
            break;
        }
    }
    return value;
}

static bool evaluate_numeric_expression(const char* text, float* value_out) {
    expr_ptr = skip_spaces_const(text);
    float value = parse_expression();
    if(*skip_spaces_const(expr_ptr) != '\0') return false;
    *value_out = value;
    return true;
}

static bool evaluate_relation(char* clause, bool* result) {
    trim(clause);
    size_t op_len = 0;
    const char* op_const = find_comparison_operator(clause, &op_len);
    if(!op_const) return false;

    char* op = (char*)op_const;
    char op_text[3] = {0};
    strncpy(op_text, op, op_len);
    op_text[op_len] = '\0';

    *op = '\0';
    char* right = op + op_len;
    trim(clause);
    trim(right);

    char left_string[MAX_STRING_LENGTH];
    char right_string[MAX_STRING_LENGTH];
    bool left_is_string = evaluate_string_value(clause, left_string, sizeof(left_string));
    bool right_is_string = evaluate_string_value(right, right_string, sizeof(right_string));

    if(left_is_string || right_is_string) {
        if(!(left_is_string && right_is_string)) return false;

        if(strcmp(op_text, "=") == 0) *result = (strcmp(left_string, right_string) == 0);
        else if(strcmp(op_text, "<>") == 0) *result = (strcmp(left_string, right_string) != 0);
        else return false;
        return true;
    }

    float left_value = 0.0f;
    float right_value = 0.0f;
    if(!evaluate_numeric_expression(clause, &left_value)) return false;
    if(!evaluate_numeric_expression(right, &right_value)) return false;

    if(strcmp(op_text, "=") == 0) *result = (left_value == right_value);
    else if(strcmp(op_text, "<>") == 0) *result = (left_value != right_value);
    else if(strcmp(op_text, "<=") == 0) *result = (left_value <= right_value);
    else if(strcmp(op_text, ">=") == 0) *result = (left_value >= right_value);
    else if(strcmp(op_text, "<") == 0) *result = (left_value < right_value);
    else if(strcmp(op_text, ">") == 0) *result = (left_value > right_value);
    else return false;

    return true;
}

static bool evaluate_condition(char* condition, bool* result) {
    char* segment = condition;
    *result = false;

    while(segment) {
        const char* or_const = find_keyword_token(segment, "OR");
        char* next_segment = NULL;
        if(or_const) {
            char* or_pos = (char*)or_const;
            *or_pos = '\0';
            next_segment = or_pos + 2;
        }

        bool clause_result = false;
        if(!evaluate_relation(segment, &clause_result)) return false;
        if(clause_result) {
            *result = true;
            return true;
        }

        segment = next_segment;
    }

    return true;
}

static int find_line_index(int number) {
    for(int i = 0; i < state.line_count; i++) {
        if(state.lines[i].number == number) return i;
    }
    return -1;
}

static int find_matching_next(int for_index) {
    int depth = 0;

    for(int i = for_index + 1; i < state.line_count; i++) {
        char line_copy[MAX_LINE_LENGTH];
        copy_text(line_copy, sizeof(line_copy), get_line_text(i));
        char* next = NULL;
        char* token = next_word(line_copy, &next);
        if(!token) continue;
        uppercase(token);

        if(strcmp(token, "FOR") == 0) {
            depth++;
        } else if(strcmp(token, "NEXT") == 0) {
            if(depth == 0) return i;
            depth--;
        }
    }

    return -1;
}

static int split_arguments(char* text, char* args[], int max_args) {
    int count = 0;
    bool in_string = false;
    int paren_depth = 0;
    char* segment = skip_spaces(text);

    if(*segment == '\0') return 0;
    args[count++] = segment;

    for(char* p = segment; *p; p++) {
        char c = *p;
        if(c == '"') {
            in_string = !in_string;
        } else if(!in_string) {
            if(c == '(') paren_depth++;
            else if((c == ')') && (paren_depth > 0)) paren_depth--;
            else if((c == ',') && (paren_depth == 0)) {
                *p = '\0';
                trim(args[count - 1]);
                if(count < max_args) args[count++] = skip_spaces(p + 1);
            }
        }
    }

    for(int i = 0; i < count; i++) trim(args[i]);
    return count;
}

static void basic_runtime_reset(void) {
    memset(state.vars, 0, sizeof(state.vars));
    memset(state.string_flags, 0, sizeof(state.string_flags));
    memset(state.string_vars, 0, sizeof(state.string_vars));
    clear_render_state();
    state.current_index = 0;
    state.steps = 0;
    state.call_depth = 0;
    state.for_depth = 0;
    state.running = true;
    state.waiting_for_input = false;
    state.waiting_var = -1;
    state.pending_input = 0;
    state.exec_paused = false;
    state.exec_pause_until = 0;
    snprintf(state.status, sizeof(state.status), "Ejecutando");
}

static bool read_program(const char* path) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    if(!storage) {
        snprintf(state.status, sizeof(state.status), "No storage disponible");
        state.loaded = false;
        return false;
    }

    File* file = storage_file_alloc(storage);
    bool ok = false;

    if(!state.program_text) {
        state.program_text = malloc(PROGRAM_BUFFER_SIZE);
    }

    char* buf = state.program_text;
    size_t total = 0;

    if(!buf) {
        snprintf(state.status, sizeof(state.status), "Sin memoria para cargar");
        storage_file_free(file);
        furi_record_close(RECORD_STORAGE);
        state.loaded = false;
        return false;
    }

    if(!storage_file_open(file, path, FSAM_READ, FSOM_OPEN_EXISTING)) {
        snprintf(state.status, sizeof(state.status), "No existe .bas");
    } else {
        while(total + 1 < PROGRAM_BUFFER_SIZE) {
            size_t read = storage_file_read(file, buf + total, PROGRAM_BUFFER_SIZE - 1 - total);
            if(read == 0) break;
            total += read;
        }

        buf[total] = '\0';
        state.line_count = 0;
        char* cursor = buf;

        while(*cursor && (state.line_count < MAX_SOURCE_LINES)) {
            char* end = cursor;
            while(*end && (*end != '\n') && (*end != '\r')) end++;

            char saved = *end;
            char* next_cursor = end;
            if(saved != '\0') {
                next_cursor++;
                while((*next_cursor == '\n') || (*next_cursor == '\r')) next_cursor++;
            }
            *end = '\0';
            trim(cursor);

            if(*cursor) {
                char* p = cursor;
                int number = 0;
                while(isdigit((unsigned char)*p)) number = number * 10 + (*p++ - '0');
                if(number > 0) {
                    p = skip_spaces(p);
                    if(*p) {
                        state.lines[state.line_count].number = number;
                        state.lines[state.line_count].offset = (uint16_t)(p - buf);
                        state.line_count++;
                    }
                }
            }

            if(saved == '\0') break;
            cursor = next_cursor;
        }

        if(state.line_count == 0) {
            snprintf(state.status, sizeof(state.status), ".bas vacio o invalido");
        } else {
            snprintf(state.status, sizeof(state.status), "%d lineas cargadas", state.line_count);
            state.loaded = true;
            ok = true;
        }
    }

    storage_file_close(file);
    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);

    if(!ok) state.loaded = false;
    return ok;
}

static void execute_statement(char* statement, int line_number) {
    char* next = NULL;
    char* token = next_word(statement, &next);
    if(!token) {
        state.current_index++;
        return;
    }

    uppercase(token);

    if(strcmp(token, "CLS") == 0) {
        clear_render_state();
        state.current_index++;
        return;
    }

    if(strcmp(token, "REM") == 0) {
        state.current_index++;
        return;
    }

    if(strcmp(token, "PRINT") == 0) {
        char* rest = skip_spaces(next);
        if(*rest == '\0') {
            append_output("");
        } else {
            char string_value[MAX_LINE_LENGTH];
            if(evaluate_string_value(rest, string_value, sizeof(string_value))) {
                append_output(string_value);
            } else {
                float numeric_value = 0.0f;
                if(!evaluate_numeric_expression(rest, &numeric_value)) {
                    stop_with_runtime_error(line_number, "PRINT invalido");
                    return;
                }
                char formatted[MAX_LINE_LENGTH];
                format_number(numeric_value, formatted, sizeof(formatted));
                append_output(formatted);
            }
        }
        state.current_index++;
        return;
    }

    if(strcmp(token, "LET") == 0) {
        char* rest = skip_spaces(next);
        if(!isalpha((unsigned char)*rest)) {
            stop_with_runtime_error(line_number, "LET sin variable");
            return;
        }

        int var_index = toupper((unsigned char)*rest) - 'A';
        rest = skip_spaces(rest + 1);
        if(*rest != '=') {
            stop_with_runtime_error(line_number, "LET sin =");
            return;
        }
        rest = skip_spaces(rest + 1);

        if(is_simple_call(rest, "GETCHAR")) {
            state.waiting_for_input = true;
            state.waiting_var = var_index;
            state.current_index++;
            snprintf(state.status, sizeof(state.status), "GETCHAR: elige 0-9");
            number_input_set_header_text(number_input, "GETCHAR 0-9");
            view_dispatcher_switch_to_view(view_dispatcher, BasicViewNumberInput);
            return;
        }

        char string_value[MAX_STRING_LENGTH];
        if(evaluate_string_value(rest, string_value, sizeof(string_value))) {
            set_string_var(var_index, string_value);
            state.current_index++;
            return;
        }

        float numeric_value = 0.0f;
        if(!evaluate_numeric_expression(rest, &numeric_value)) {
            stop_with_runtime_error(line_number, "LET invalido");
            return;
        }

        set_numeric_var(var_index, numeric_value);
        state.current_index++;
        return;
    }

    if(strcmp(token, "GOTO") == 0) {
        int destination = 0;
        if(!parse_line_number_token(next, &destination)) {
            stop_with_runtime_error(line_number, "GOTO invalido");
            return;
        }

        int target = find_line_index(destination);
        if(target < 0) {
            stop_with_runtime_error(line_number, "Linea GOTO inexistente");
            return;
        }

        state.current_index = target;
        return;
    }

    if(strcmp(token, "GOSUB") == 0) {
        int destination = 0;
        if(!parse_line_number_token(next, &destination)) {
            stop_with_runtime_error(line_number, "GOSUB invalido");
            return;
        }

        if(state.call_depth >= MAX_CALL_STACK) {
            stop_with_runtime_error(line_number, "Stack GOSUB lleno");
            return;
        }

        int target = find_line_index(destination);
        if(target < 0) {
            stop_with_runtime_error(line_number, "Linea GOSUB inexistente");
            return;
        }

        state.call_stack[state.call_depth++] = state.current_index + 1;
        state.current_index = target;
        return;
    }

    if(strcmp(token, "RETURN") == 0) {
        if(state.call_depth <= 0) {
            stop_with_runtime_error(line_number, "RETURN sin GOSUB");
            return;
        }

        state.current_index = state.call_stack[--state.call_depth];
        return;
    }

    if(strcmp(token, "FOR") == 0) {
        char* rest = skip_spaces(next);
        if(!isalpha((unsigned char)*rest)) {
            stop_with_runtime_error(line_number, "FOR sin variable");
            return;
        }

        int var_index = toupper((unsigned char)*rest) - 'A';
        rest = skip_spaces(rest + 1);
        if(*rest != '=') {
            stop_with_runtime_error(line_number, "FOR sin =");
            return;
        }

        rest = skip_spaces(rest + 1);
        const char* to_const = find_keyword_token(rest, "TO");
        if(!to_const) {
            stop_with_runtime_error(line_number, "FOR sin TO");
            return;
        }

        char work[MAX_LINE_LENGTH];
        copy_text(work, sizeof(work), rest);
        char* to_pos = (char*)find_keyword_token(work, "TO");
        char* end_expr = NULL;
        char* step_expr = NULL;
        *to_pos = '\0';
        end_expr = to_pos + 2;

        char* step_pos = (char*)find_keyword_token(end_expr, "STEP");
        if(step_pos) {
            *step_pos = '\0';
            step_expr = step_pos + 4;
        }

        trim(work);
        trim(end_expr);
        if(step_expr) trim(step_expr);

        float start_value = 0.0f;
        float end_value = 0.0f;
        float step_value = 1.0f;

        if(!evaluate_numeric_expression(work, &start_value) ||
           !evaluate_numeric_expression(end_expr, &end_value) ||
           (step_expr && !evaluate_numeric_expression(step_expr, &step_value))) {
            stop_with_runtime_error(line_number, "FOR invalido");
            return;
        }

        if(step_value == 0.0f) {
            stop_with_runtime_error(line_number, "FOR STEP 0");
            return;
        }

        set_numeric_var(var_index, start_value);
        bool should_run = (step_value > 0.0f) ? (start_value <= end_value) : (start_value >= end_value);
        if(!should_run) {
            int next_index = find_matching_next(state.current_index);
            if(next_index < 0) {
                stop_with_runtime_error(line_number, "NEXT no encontrado");
                return;
            }
            state.current_index = next_index + 1;
            return;
        }

        if(state.for_depth >= MAX_FOR_STACK) {
            stop_with_runtime_error(line_number, "Stack FOR lleno");
            return;
        }

        state.for_stack[state.for_depth].var_index = var_index;
        state.for_stack[state.for_depth].end_value = end_value;
        state.for_stack[state.for_depth].step_value = step_value;
        state.for_stack[state.for_depth].loop_index = state.current_index + 1;
        state.for_depth++;
        state.current_index++;
        return;
    }

    if(strcmp(token, "NEXT") == 0) {
        if(state.for_depth <= 0) {
            stop_with_runtime_error(line_number, "NEXT sin FOR");
            return;
        }

        BasicForFrame* frame = &state.for_stack[state.for_depth - 1];
        char* rest = skip_spaces(next);
        if(*rest) {
            int var_index = 0;
            if(!parse_single_var_token(rest, &var_index) || (var_index != frame->var_index)) {
                stop_with_runtime_error(line_number, "NEXT variable incorrecta");
                return;
            }
        }

        state.vars[frame->var_index] += frame->step_value;
        float current_value = state.vars[frame->var_index];
        bool continue_loop = (frame->step_value > 0.0f) ? (current_value <= frame->end_value) :
                                                        (current_value >= frame->end_value);
        if(continue_loop) {
            state.current_index = frame->loop_index;
        } else {
            state.for_depth--;
            state.current_index++;
        }
        return;
    }

    if(strcmp(token, "PLOT") == 0) {
        char args_buffer[MAX_LINE_LENGTH];
        copy_text(args_buffer, sizeof(args_buffer), next);
        char* args[3] = {0};
        int arg_count = split_arguments(args_buffer, args, 3);
        if(arg_count < 2) {
            stop_with_runtime_error(line_number, "PLOT invalido");
            return;
        }

        float x = 0.0f;
        float y = 0.0f;
        if(!evaluate_numeric_expression(args[0], &x) || !evaluate_numeric_expression(args[1], &y)) {
            stop_with_runtime_error(line_number, "PLOT invalido");
            return;
        }

        add_plot_point(x, y);
        state.current_index++;
        return;
    }

    if(strcmp(token, "LINE") == 0) {
        char args_buffer[MAX_LINE_LENGTH];
        copy_text(args_buffer, sizeof(args_buffer), next);
        char* largs[4] = {0};
        int larg_count = split_arguments(args_buffer, largs, 4);
        if(larg_count < 4) {
            stop_with_runtime_error(line_number, "LINE invalido");
            return;
        }
        float lx1 = 0.0f, ly1 = 0.0f, lx2 = 0.0f, ly2 = 0.0f;
        if(!evaluate_numeric_expression(largs[0], &lx1) ||
           !evaluate_numeric_expression(largs[1], &ly1) ||
           !evaluate_numeric_expression(largs[2], &lx2) ||
           !evaluate_numeric_expression(largs[3], &ly2)) {
            stop_with_runtime_error(line_number, "LINE invalido");
            return;
        }
        int bx1 = round_to_int(lx1), by1 = round_to_int(ly1);
        int bx2 = round_to_int(lx2), by2 = round_to_int(ly2);
        int ldx = abs(bx2 - bx1);
        int lsx = (bx1 < bx2) ? 1 : -1;
        int ldy = -abs(by2 - by1);
        int lsy = (by1 < by2) ? 1 : -1;
        int lerr = ldx + ldy;
        int lsafety = ldx - ldy + 2;
        while(lsafety-- > 0) {
            add_plot_point((float)bx1, (float)by1);
            if((bx1 == bx2) && (by1 == by2)) break;
            int le2 = 2 * lerr;
            if(le2 >= ldy) { lerr += ldy; bx1 += lsx; }
            if(le2 <= ldx) { lerr += ldx; by1 += lsy; }
        }
        state.current_index++;
        return;
    }

    if(strcmp(token, "PAUSE") == 0) {
        float pause_value = 0.0f;
        if(!evaluate_numeric_expression(next, &pause_value)) {
            stop_with_runtime_error(line_number, "PAUSE invalido");
            return;
        }
        if(pause_value < 0.0f) pause_value = 0.0f;
        if(pause_value > 10000.0f) pause_value = 10000.0f;
        state.exec_paused = true;
        state.exec_pause_until = furi_get_tick() + (uint32_t)pause_value;
        state.current_index++;
        return;
    }

    if(strcmp(token, "IF") == 0) {
        char work[MAX_LINE_LENGTH];
        copy_text(work, sizeof(work), next);
        char* then_pos = (char*)find_keyword_token(work, "THEN");
        if(!then_pos) {
            stop_with_runtime_error(line_number, "IF sin THEN");
            return;
        }

        *then_pos = '\0';
        char* then_stmt = then_pos + 4;
        trim(work);
        trim(then_stmt);

        bool condition = false;
        if(!evaluate_condition(work, &condition)) {
            stop_with_runtime_error(line_number, "IF invalido");
            return;
        }

        if(condition) {
            execute_statement(then_stmt, line_number);
        } else {
            state.current_index++;
        }
        return;
    }

    if(strcmp(token, "END") == 0) {
        state.running = false;
        snprintf(state.status, sizeof(state.status), "Programa finalizado");
        return;
    }

    {
        char detail[MAX_LINE_LENGTH];
        snprintf(detail, sizeof(detail), "Sentencia no soportada: %s", token);
        stop_with_runtime_error(line_number, detail);
    }
}

static void execute_program_slice(void) {
    int budget = STEPS_PER_TICK;
    while(state.running && !state.waiting_for_input && !state.exec_paused &&
          (state.current_index < state.line_count)) {
        if(--budget < 0) return;
        char statement[MAX_LINE_LENGTH];
        int line_number = state.lines[state.current_index].number;
        copy_text(statement, sizeof(statement), get_line_text(state.current_index));
        execute_statement(statement, line_number);
    }
    if(!state.waiting_for_input && !state.exec_paused && state.running &&
       (state.current_index >= state.line_count)) {
        state.running = false;
        snprintf(state.status, sizeof(state.status), "Fin del programa");
    }
}

/* ─── EDITOR helpers ──────────────────────────────────────────────────────── */

static void editor_load_from_state(void) {
    editor_line_count = 0;
    editor_cursor = 0;
    for(int i = 0; i < state.line_count && i < MAX_EDITOR_LINES; i++) {
        snprintf(
            editor_lines[i],
            MAX_EDITOR_LINE_LEN,
            "%d %s",
            state.lines[i].number,
            get_line_text(i));
        editor_line_count++;
    }
}

static bool editor_save_to_state(void) {
    if(!state.program_text) {
        state.program_text = malloc(PROGRAM_BUFFER_SIZE);
        if(!state.program_text) return false;
    }

    char* buf = state.program_text;
    size_t pos = 0;
    for(int i = 0; i < editor_line_count; i++) {
        size_t len = strlen(editor_lines[i]);
        if(pos + len + 2 >= PROGRAM_BUFFER_SIZE) break;
        memcpy(buf + pos, editor_lines[i], len);
        pos += len;
        buf[pos++] = '\n';
    }
    buf[pos] = '\0';

    /* re-parse lines[] from buffer */
    state.line_count = 0;
    char* cursor = buf;
    while(*cursor && state.line_count < MAX_SOURCE_LINES) {
        char* end = cursor;
        while(*end && *end != '\n' && *end != '\r') end++;
        char saved = *end;
        char* next_cursor = end;
        if(saved != '\0') {
            next_cursor++;
            while(*next_cursor == '\n' || *next_cursor == '\r') next_cursor++;
        }
        *end = '\0';
        /* trim in-place */
        char* p = cursor;
        while(*p && (*p == ' ' || *p == '\t')) p++;
        if(*p) {
            int number = 0;
            while(*p >= '0' && *p <= '9') number = number * 10 + (*p++ - '0');
            if(number > 0) {
                while(*p == ' ' || *p == '\t') p++;
                if(*p) {
                    state.lines[state.line_count].number = number;
                    state.lines[state.line_count].offset = (uint16_t)(p - buf);
                    state.line_count++;
                }
            }
        }
        if(saved == '\0') break;
        cursor = next_cursor;
    }

    state.loaded = (state.line_count > 0);
    if(state.loaded) {
        snprintf(state.status, sizeof(state.status), "%d lineas cargadas", state.line_count);
    } else {
        snprintf(state.status, sizeof(state.status), "Programa vacio");
    }
    return state.loaded;
}

static void editor_insert_line_after_cursor(void) {
    if(editor_line_count >= MAX_EDITOR_LINES) return;
    int ins = editor_cursor + 1;
    for(int i = editor_line_count; i > ins; i--) {
        memcpy(editor_lines[i], editor_lines[i - 1], MAX_EDITOR_LINE_LEN);
    }
    editor_lines[ins][0] = '\0';
    editor_line_count++;
    editor_cursor = ins;
}

static void editor_delete_cursor_line(void) {
    if(editor_line_count == 0) return;
    for(int i = editor_cursor; i < editor_line_count - 1; i++) {
        memcpy(editor_lines[i], editor_lines[i + 1], MAX_EDITOR_LINE_LEN);
    }
    editor_line_count--;
    if(editor_cursor >= editor_line_count && editor_cursor > 0) editor_cursor--;
}

static void rebuild_editor_view(void) {
    if(!editor_view) return;
    with_view_model(
        editor_view,
        BasicEditorViewModel * m,
        {
            /* keep cursor visible */
            int visible = 4;
            if(editor_cursor < m->scroll) m->scroll = editor_cursor;
            if(editor_cursor >= m->scroll + visible) m->scroll = editor_cursor - visible + 1;
            if(m->scroll < 0) m->scroll = 0;
        },
        true);
}

static void basic_editor_view_draw_callback(Canvas* canvas, void* model) {
    BasicEditorViewModel* m = model;
    canvas_clear(canvas);

    /* header */
    canvas_set_color(canvas, ColorBlack);
    canvas_draw_box(canvas, 0, 0, 128, 12);
    canvas_set_color(canvas, ColorWhite);
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str(canvas, 3, 9, "EDITOR");
    char info[16];
    snprintf(info, sizeof(info), "%d ln", editor_line_count);
    canvas_draw_str_aligned(canvas, 125, 2, AlignRight, AlignTop, info);
    canvas_set_color(canvas, ColorBlack);

    canvas_set_font(canvas, FontSecondary);

    int visible = 4;
    int scroll = m->scroll;
    if(editor_line_count == 0) {
        canvas_draw_str_aligned(canvas, 64, 28, AlignCenter, AlignTop, "Vacio. OK=nueva linea");
    } else {
        for(int i = 0; i < visible; i++) {
            int idx = scroll + i;
            if(idx >= editor_line_count) break;
            int row_y = 13 + i * 12;
            bool sel = (idx == editor_cursor);
            if(sel) {
                canvas_set_color(canvas, ColorBlack);
                canvas_draw_box(canvas, 0, row_y, 128, 12);
                canvas_set_color(canvas, ColorWhite);
            }
            char trimmed[22];
            format_trimmed_text(editor_lines[idx], trimmed, sizeof(trimmed), 20);
            canvas_draw_str(canvas, 2, row_y + 9, trimmed);
            if(sel) canvas_set_color(canvas, ColorBlack);
        }
    }

    /* footer */
    elements_button_left(canvas, "Open");
    elements_button_center(canvas, "Edit");
    elements_button_right(canvas, "Run");
}

static bool basic_editor_view_input_callback(InputEvent* event, void* context) {
    UNUSED(context);

    if(event->type == InputTypeShort) {
        if(event->key == InputKeyUp) {
            if(editor_cursor > 0) editor_cursor--;
            rebuild_editor_view();
            return true;
        }
        if(event->key == InputKeyDown) {
            if(editor_cursor < editor_line_count - 1) editor_cursor++;
            rebuild_editor_view();
            return true;
        }
        if(event->key == InputKeyOk) {
            /* edit current line (or create first) */
            if(editor_line_count == 0) {
                editor_insert_line_after_cursor();
                editor_cursor = 0;
            }
            copy_text(editor_text_buf, MAX_EDITOR_LINE_LEN, editor_lines[editor_cursor]);
            text_input_set_header_text(text_input_editor, "Editar linea:");
            text_input_set_result_callback(
                text_input_editor,
                NULL, /* set in main via custom event */
                NULL,
                editor_text_buf,
                MAX_EDITOR_LINE_LEN,
                false);
            view_dispatcher_send_custom_event(
                view_dispatcher, (uint32_t)BasicCustomEventEditorEditDone - 1);
            /* switch to TextInput immediately */
            view_dispatcher_switch_to_view(view_dispatcher, BasicViewTextInput);
            return true;
        }
        if(event->key == InputKeyBack) {
            view_dispatcher_send_custom_event(view_dispatcher, BasicCustomEventExit);
            return true;
        }
        if(event->key == InputKeyRight) {
            view_dispatcher_send_custom_event(view_dispatcher, BasicCustomEventEditorRun);
            return true;
        }
        if(event->key == InputKeyLeft) {
            /* Open file browser */
            view_dispatcher_send_custom_event(view_dispatcher, BasicCustomEventOpenBrowser);
            return true;
        }
    }

    if(event->type == InputTypeLong) {
        if(event->key == InputKeyOk) {
            /* insert new line */
            editor_insert_line_after_cursor();
            copy_text(editor_text_buf, MAX_EDITOR_LINE_LEN, "");
            text_input_set_header_text(text_input_editor, "Nueva linea:");
            text_input_set_result_callback(
                text_input_editor,
                NULL,
                NULL,
                editor_text_buf,
                MAX_EDITOR_LINE_LEN,
                true);
            view_dispatcher_send_custom_event(
                view_dispatcher, (uint32_t)BasicCustomEventEditorEditDone - 1);
            view_dispatcher_switch_to_view(view_dispatcher, BasicViewTextInput);
            return true;
        }
        if(event->key == InputKeyBack) {
            /* Long back = delete current line */
            editor_delete_cursor_line();
            rebuild_editor_view();
            return true;
        }
    }

    return false;
}

static void editor_text_input_callback(void* context) {
    UNUSED(context);
    view_dispatcher_send_custom_event(view_dispatcher, BasicCustomEventEditorEditDone);
}

static void basic_main_view_draw_callback(Canvas* canvas, void* model) {
    UNUSED(model);
    canvas_clear(canvas);

    // ── Header bar ────────────────────────────────────────────────────────────
    canvas_set_color(canvas, ColorBlack);
    canvas_draw_box(canvas, 0, 0, 128, 12);
    canvas_set_color(canvas, ColorWhite);
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str(canvas, 3, 9, "BASIC Interpreter");
    char badge[10];
    get_execution_status_badge(badge, sizeof(badge));
    canvas_draw_str_aligned(canvas, 125, 2, AlignRight, AlignTop, badge);
    canvas_set_color(canvas, ColorBlack);

    // ── Content ───────────────────────────────────────────────────────────────
    canvas_set_font(canvas, FontSecondary);

    char name[MAX_LINE_LENGTH];
    get_program_name(name, sizeof(name));
    char* ndot = strrchr(name, '.');
    if(ndot) *ndot = '\0';
    char name_short[24];
    format_trimmed_text(name, name_short, sizeof(name_short), 22);
    canvas_draw_str(canvas, 3, 24, name_short);

    char status_short[24];
    format_trimmed_text(state.status, status_short, sizeof(status_short), 22);
    canvas_draw_str(canvas, 3, 35, status_short);

    if(state.output_count > 0) {
        char last_out[24];
        format_trimmed_text(
            state.output[state.output_count - 1], last_out, sizeof(last_out), 21);
        canvas_draw_str(canvas, 3, 46, last_out);
    }

    // ── Bottom buttons ────────────────────────────────────────────────────────
    elements_button_left(canvas, "Exit");
    elements_button_center(canvas, "Open");
    elements_button_right(canvas, "Run");
}

static bool basic_main_view_input_callback(InputEvent* event, void* context) {
    UNUSED(context);
    if(event->type != InputTypeShort) return false;

    if(event->key == InputKeyLeft) {
        view_dispatcher_send_custom_event(view_dispatcher, BasicCustomEventExit);
        return true;
    }
    if(event->key == InputKeyOk) {
        view_dispatcher_send_custom_event(view_dispatcher, BasicCustomEventOpenBrowser);
        return true;
    }
    if(event->key == InputKeyRight) {
        view_dispatcher_send_custom_event(view_dispatcher, BasicCustomEventRunProgram);
        return true;
    }
    if(event->key == InputKeyBack) {
        view_dispatcher_send_custom_event(view_dispatcher, BasicCustomEventExit);
        return true;
    }
    return false;
}

static void rebuild_main_view(void) {
    if(!main_view) return;
    with_view_model(
        main_view,
        BasicMainViewModel * model,
        { model->redraw_token++; },
        true);
}

static void basic_execution_view_draw_callback(Canvas* canvas, void* model) {
    BasicExecutionViewModel* view_model = model;
    bool has_plot = state.plot_count > 0;
    int visible_lines = get_execution_visible_lines();

    int max_start = get_execution_max_start_line();
    int start_line = view_model->output_scroll;
    if(start_line < 0) start_line = 0;
    if(start_line > max_start) start_line = max_start;

    canvas_clear(canvas);

    char name_buf[48];
    char name_short[18];
    char badge[10];
    get_program_name(name_buf, sizeof(name_buf));
    {
        char* dot = strrchr(name_buf, '.');
        if(dot) *dot = '\0';
    }
    format_trimmed_text(name_buf, name_short, sizeof(name_short), 14);
    get_execution_status_badge(badge, sizeof(badge));

    if(has_plot) {
        // ── Animacion: plot pantalla completa 1:1, header+footer overlay ────
        canvas_set_color(canvas, ColorBlack);
        for(int i = 0; i < state.plot_count; i++) {
            canvas_draw_dot(canvas, (int32_t)state.plots[i].x, (int32_t)state.plots[i].y);
        }
        // Header overlay (y 0-10)
        canvas_draw_box(canvas, 0, 0, 128, 11);
        canvas_set_color(canvas, ColorWhite);
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str(canvas, 3, 8, name_short);
        canvas_draw_str_aligned(canvas, 125, 1, AlignRight, AlignTop, badge);
        canvas_set_color(canvas, ColorBlack);
        // Footer overlay (y 53-63)
        canvas_draw_box(canvas, 0, 53, 128, 11);
        canvas_set_color(canvas, ColorWhite);
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str(canvas, 3, 61, "< Back");
        if(!state.running) {
            canvas_draw_str_aligned(canvas, 125, 54, AlignRight, AlignTop, "Run >");
        }
        canvas_set_color(canvas, ColorBlack);
    } else {
        // ── Modo texto ───────────────────────────────────────────────────────
        canvas_set_color(canvas, ColorBlack);
        canvas_draw_box(canvas, 0, 0, 128, 12);
        canvas_set_color(canvas, ColorWhite);
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str(canvas, 3, 9, name_short);
        canvas_draw_str_aligned(canvas, 125, 2, AlignRight, AlignTop, badge);
        canvas_set_color(canvas, ColorBlack);

        canvas_set_font(canvas, FontSecondary);
        canvas_draw_line(canvas, 0, 12, 127, 12);

        if(state.output_count == 0) {
            char msg[26];
            format_trimmed_text(state.status, msg, sizeof(msg), 21);
            canvas_draw_str_aligned(canvas, 64, 32, AlignCenter, AlignTop, msg);
        } else {
            int end_line = start_line + visible_lines;
            if(end_line > state.output_count) end_line = state.output_count;
            int draw_y = 22;
            for(int i = start_line; i < end_line; i++) {
                draw_trimmed_text(canvas, 3, draw_y, state.output[i], 20);
                draw_y += 10;
            }
            if(state.output_count > visible_lines) {
                draw_execution_scrollbar(
                    canvas, 124, 14, 37,
                    state.output_count, visible_lines, start_line);
            }
        }

        elements_button_left(canvas, "Back");
        elements_button_right(canvas, "Run");
    }
}

static bool basic_execution_view_input_callback(InputEvent* event, void* context) {
    UNUSED(context);

    if((event->type != InputTypeShort) && (event->type != InputTypeRepeat)) return false;

    if(event->key == InputKeyUp) {
        bool updated = false;
        with_view_model(
            execution_view,
            BasicExecutionViewModel * model,
            {
                if(model->output_scroll > 0) {
                    model->output_scroll--;
                    model->redraw_token++;
                    updated = true;
                }
            },
            updated);
        return updated;
    }

    if(event->key == InputKeyDown) {
        bool updated = false;
        with_view_model(
            execution_view,
            BasicExecutionViewModel * model,
            {
                int max_start = get_execution_max_start_line();
                if(model->output_scroll < max_start) {
                    model->output_scroll++;
                    model->redraw_token++;
                    updated = true;
                }
            },
            updated);
        return updated;
    }

    if((event->key == InputKeyLeft) || (event->key == InputKeyBack)) {
        view_dispatcher_send_custom_event(view_dispatcher, BasicCustomEventBackToMain);
        return true;
    }

    if(event->key == InputKeyRight) {
        view_dispatcher_send_custom_event(view_dispatcher, BasicCustomEventRunProgram);
        return true;
    }

    return false;
}

static void rebuild_execution_widget(void) {
    if(!execution_view) return;
    with_view_model(
        execution_view,
        BasicExecutionViewModel * model,
        {
            int max_start = get_execution_max_start_line();
            if(model->output_scroll < 0) model->output_scroll = 0;
            if(model->output_scroll > max_start) model->output_scroll = max_start;
            model->redraw_token++;
        },
        true);
}

static void basic_number_input_result_callback(void* context, int32_t number) {
    UNUSED(context);
    state.pending_input = number;
    view_dispatcher_send_custom_event(view_dispatcher, BasicCustomEventInputReady);
}

static uint32_t basic_number_input_previous_callback(void* context) {
    UNUSED(context);
    view_dispatcher_send_custom_event(view_dispatcher, BasicCustomEventInputCancelled);
    return BasicViewExecution;
}

static void exec_timer_callback(void* ctx) {
    UNUSED(ctx);
    view_dispatcher_send_custom_event(view_dispatcher, BasicCustomEventTick);
}

static bool basic_app_navigation_callback(void* context) {
    UNUSED(context);
    view_dispatcher_stop(view_dispatcher);
    return true;
}

static bool basic_custom_event_callback(void* context, uint32_t event) {
    UNUSED(context);

    if(event == BasicCustomEventExit) {
        view_dispatcher_stop(view_dispatcher);
        return true;
    }

    if(event == BasicCustomEventBackToMain) {
        furi_timer_stop(exec_timer);
        state.running = false;
        state.exec_paused = false;
        rebuild_editor_view();
        view_dispatcher_switch_to_view(view_dispatcher, BasicViewEditor);
        return true;
    }

    if(event == BasicCustomEventOpenBrowser) {
        DialogsFileBrowserOptions opts;
        dialog_file_browser_set_basic_options(&opts, ".bas", NULL);
        opts.base_path = "/ext/basic";
        opts.skip_assets = true;
        opts.hide_dot_files = true;

        FuriString* selected = furi_string_alloc_set(furi_string_get_cstr(program_path));
        bool chosen = dialog_file_browser_show(dialogs, selected, program_path, &opts);
        if(chosen) {
            furi_string_set(program_path, furi_string_get_cstr(selected));
            clear_render_state();
            read_program(furi_string_get_cstr(program_path));
            editor_load_from_state();
            editor_cursor = 0;
            rebuild_editor_view();
            view_dispatcher_switch_to_view(view_dispatcher, BasicViewEditor);
        } else {
            rebuild_main_view();
        }
        furi_string_free(selected);
        return true;
    }

    if(event == BasicCustomEventEditorEditDone) {
        /* copy text_buf result back to the current editor line */
        if(editor_cursor >= 0 && editor_cursor < editor_line_count) {
            copy_text(editor_lines[editor_cursor], MAX_EDITOR_LINE_LEN, editor_text_buf);
        }
        rebuild_editor_view();
        view_dispatcher_switch_to_view(view_dispatcher, BasicViewEditor);
        return true;
    }

    if(event == BasicCustomEventEditorRun) {
        furi_timer_stop(exec_timer);
        if(editor_save_to_state()) {
            basic_runtime_reset();
            number_input_set_result_callback(
                number_input, basic_number_input_result_callback, NULL, 0, 0, 9);
            rebuild_execution_widget();
            view_dispatcher_switch_to_view(view_dispatcher, BasicViewExecution);
            furi_timer_start(exec_timer, 1);
        } else {
            rebuild_editor_view();
        }
        return true;
    }

    if(event == BasicCustomEventRunProgram) {
        furi_timer_stop(exec_timer);
        if(read_program(furi_string_get_cstr(program_path))) {
            basic_runtime_reset();
            number_input_set_result_callback(
                number_input, basic_number_input_result_callback, NULL, 0, 0, 9);
            rebuild_execution_widget();
            view_dispatcher_switch_to_view(view_dispatcher, BasicViewExecution);
            furi_timer_start(exec_timer, 1);
        } else {
            append_output("Error leyendo .bas");
            rebuild_main_view();
        }
        return true;
    }

    if(event == BasicCustomEventInputReady) {
        if(state.waiting_for_input && (state.waiting_var >= 0) && (state.waiting_var < MAX_VARIABLES)) {
            set_getchar_var(state.waiting_var, state.pending_input);
            state.waiting_for_input = false;
            state.waiting_var = -1;
            snprintf(state.status, sizeof(state.status), "Entrada recibida");
            view_dispatcher_switch_to_view(view_dispatcher, BasicViewExecution);
            rebuild_execution_widget();
            furi_timer_start(exec_timer, 1);
        }
        return true;
    }

    if(event == BasicCustomEventInputCancelled) {
        if(state.waiting_for_input) {
            furi_timer_stop(exec_timer);
            state.waiting_for_input = false;
            state.running = false;
            state.waiting_var = -1;
            snprintf(state.status, sizeof(state.status), "Entrada cancelada");
            append_output("GETCHAR cancelado");
            scroll_execution_to_bottom();
            rebuild_execution_widget();
            view_dispatcher_switch_to_view(view_dispatcher, BasicViewExecution);
        }
        return true;
    }

    if(event == BasicCustomEventTick) {
        if(state.exec_paused) {
            if((int32_t)(furi_get_tick() - state.exec_pause_until) >= 0) {
                state.exec_paused = false;
            }
        }
        if(state.running && !state.waiting_for_input && !state.exec_paused) {
            execute_program_slice();
        }
        if(state.running && !state.waiting_for_input) {
            if(state.exec_paused) {
                uint32_t now = furi_get_tick();
                uint32_t remaining = (state.exec_pause_until > now)
                                         ? (state.exec_pause_until - now)
                                         : 1;
                furi_timer_start(exec_timer, remaining);
            } else {
                view_dispatcher_send_custom_event(view_dispatcher, BasicCustomEventTick);
            }
        } else {
            scroll_execution_to_bottom();
            rebuild_execution_widget();
        }
        return true;
    }

    return false;
}

int32_t basic_interpreter_main(void* parameter) {
    UNUSED(parameter);

    memset(&state, 0, sizeof(state));
    snprintf(state.status, sizeof(state.status), "NO .bas cargado");

    program_path = furi_string_alloc_set(DEFAULT_PROGRAM_PATH);
    view_dispatcher = view_dispatcher_alloc();

    main_view = view_alloc();
    view_allocate_model(main_view, ViewModelTypeLocking, sizeof(BasicMainViewModel));
    view_set_context(main_view, NULL);
    view_set_draw_callback(main_view, basic_main_view_draw_callback);
    view_set_input_callback(main_view, basic_main_view_input_callback);

    execution_view = view_alloc();
    view_allocate_model(execution_view, ViewModelTypeLocking, sizeof(BasicExecutionViewModel));
    view_set_context(execution_view, NULL);
    view_set_draw_callback(execution_view, basic_execution_view_draw_callback);
    view_set_input_callback(execution_view, basic_execution_view_input_callback);

    editor_view = view_alloc();
    view_allocate_model(editor_view, ViewModelTypeLocking, sizeof(BasicEditorViewModel));
    view_set_context(editor_view, NULL);
    view_set_draw_callback(editor_view, basic_editor_view_draw_callback);
    view_set_input_callback(editor_view, basic_editor_view_input_callback);

    text_input_editor = text_input_alloc();
    text_input_set_header_text(text_input_editor, "Editar linea:");
    text_input_set_result_callback(
        text_input_editor, editor_text_input_callback, NULL,
        editor_text_buf, MAX_EDITOR_LINE_LEN, false);

    number_input = number_input_alloc();
    dialogs = furi_record_open(RECORD_DIALOGS);

    exec_timer = furi_timer_alloc(exec_timer_callback, FuriTimerTypeOnce, NULL);

    view_set_previous_callback(number_input_get_view(number_input), basic_number_input_previous_callback);
    number_input_set_header_text(number_input, "GETCHAR 0-9");
    number_input_set_result_callback(number_input, basic_number_input_result_callback, NULL, 0, 0, 9);

    view_dispatcher_set_event_callback_context(view_dispatcher, NULL);
    view_dispatcher_set_navigation_event_callback(view_dispatcher, basic_app_navigation_callback);
    view_dispatcher_set_custom_event_callback(view_dispatcher, basic_custom_event_callback);

    view_dispatcher_add_view(view_dispatcher, BasicViewMain, main_view);
    view_dispatcher_add_view(view_dispatcher, BasicViewExecution, execution_view);
    view_dispatcher_add_view(view_dispatcher, BasicViewEditor, editor_view);
    view_dispatcher_add_view(view_dispatcher, BasicViewTextInput, text_input_get_view(text_input_editor));
    view_dispatcher_add_view(view_dispatcher, BasicViewNumberInput, number_input_get_view(number_input));

    Gui* gui = furi_record_open(RECORD_GUI);
    view_dispatcher_attach_to_gui(view_dispatcher, gui, ViewDispatcherTypeFullscreen);

    /* Arrancar directo en el editor, como un micro de los 80 */
    editor_line_count = 0;
    editor_cursor = 0;
    rebuild_editor_view();
    view_dispatcher_switch_to_view(view_dispatcher, BasicViewEditor);
    view_dispatcher_run(view_dispatcher);

    furi_timer_stop(exec_timer);
    furi_timer_free(exec_timer);
    view_dispatcher_remove_view(view_dispatcher, BasicViewNumberInput);
    view_dispatcher_remove_view(view_dispatcher, BasicViewTextInput);
    view_dispatcher_remove_view(view_dispatcher, BasicViewEditor);
    view_dispatcher_remove_view(view_dispatcher, BasicViewExecution);
    view_dispatcher_remove_view(view_dispatcher, BasicViewMain);
    number_input_free(number_input);
    text_input_free(text_input_editor);
    view_free(editor_view);
    view_free(execution_view);
    view_free(main_view);
    view_dispatcher_free(view_dispatcher);
    furi_string_free(program_path);
    free(state.program_text);
    furi_record_close(RECORD_DIALOGS);
    furi_record_close(RECORD_GUI);

    return 0;
}
