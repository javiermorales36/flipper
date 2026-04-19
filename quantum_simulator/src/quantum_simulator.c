#include <furi.h>
#include <furi_hal_random.h>

#include <gui/gui.h>
#include <gui/view_port.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#define STATUS_TEXT_SIZE 64

typedef struct {
    float state[4];
    char status[STATUS_TEXT_SIZE];
    bool relay_on;
    char info[STATUS_TEXT_SIZE];
    bool help_visible;
} QuantumApp;

static void quantum_set_status(QuantumApp* app, const char* text) {
    snprintf(app->status, STATUS_TEXT_SIZE, "%s", text);
}

static void quantum_set_info(QuantumApp* app, const char* text) {
    snprintf(app->info, STATUS_TEXT_SIZE, "%s", text);
}

static void quantum_draw_help(Canvas* canvas) {
    canvas_clear(canvas);
    canvas_draw_str_aligned(canvas, 64, 6, AlignCenter, AlignTop, "AYUDA");
    canvas_draw_str(canvas, 8, 18, "OK corto: CNOT");
    canvas_draw_str(canvas, 8, 28, "OK largo: ayuda");
    canvas_draw_str(canvas, 8, 38, "Flechas: H/X");
    canvas_draw_str(canvas, 8, 48, "Back: medir");
    canvas_draw_str(canvas, 8, 58, "Back largo: salir");
}

static void quantum_apply_h0(QuantumApp* app) {
    float a0 = app->state[0];
    float a1 = app->state[1];
    float a2 = app->state[2];
    float a3 = app->state[3];
    float inv = 0.70710678f;
    app->state[0] = (a0 + a2) * inv;
    app->state[1] = (a1 + a3) * inv;
    app->state[2] = (a0 - a2) * inv;
    app->state[3] = (a1 - a3) * inv;
    quantum_set_status(app, "H0");
    quantum_set_info(app, "U:H0");
}

static void quantum_apply_h1(QuantumApp* app) {
    float a0 = app->state[0];
    float a1 = app->state[1];
    float a2 = app->state[2];
    float a3 = app->state[3];
    float inv = 0.70710678f;
    app->state[0] = (a0 + a1) * inv;
    app->state[1] = (a0 - a1) * inv;
    app->state[2] = (a2 + a3) * inv;
    app->state[3] = (a2 - a3) * inv;
    quantum_set_status(app, "H1");
    quantum_set_info(app, "D:H1");
}

static void quantum_apply_x0(QuantumApp* app) {
    float tmp0 = app->state[0];
    app->state[0] = app->state[2];
    app->state[2] = tmp0;
    float tmp1 = app->state[1];
    app->state[1] = app->state[3];
    app->state[3] = tmp1;
    quantum_set_status(app, "X0");
    quantum_set_info(app, "L:X0");
}

static void quantum_apply_x1(QuantumApp* app) {
    float tmp0 = app->state[0];
    app->state[0] = app->state[1];
    app->state[1] = tmp0;
    float tmp2 = app->state[2];
    app->state[2] = app->state[3];
    app->state[3] = tmp2;
    quantum_set_status(app, "X1");
    quantum_set_info(app, "R:X1");
}

static void quantum_apply_cnot(QuantumApp* app) {
    float tmp = app->state[2];
    app->state[2] = app->state[3];
    app->state[3] = tmp;
    quantum_set_status(app, "CNOT");
    quantum_set_info(app, "O:CNOT B:MEAS");
}

static void quantum_measure(QuantumApp* app) {
    float probabilities[4];
    float sum = 0.0f;
    for(int i = 0; i < 4; i++) {
        probabilities[i] = app->state[i] * app->state[i];
        sum += probabilities[i];
    }
    if(sum > 0.0f) {
        for(int i = 0; i < 4; i++) {
            probabilities[i] /= sum;
        }
    }

    uint32_t rnd = furi_hal_random_get();
    uint64_t threshold = 0;
    int result = 0;
    for(int i = 0; i < 4; i++) {
        threshold += (uint64_t)(probabilities[i] * 4294967295.0f);
        if(rnd <= threshold) {
            result = i;
            break;
        }
    }

    for(int i = 0; i < 4; i++) {
        app->state[i] = (i == result) ? 1.0f : 0.0f;
    }
    app->relay_on = (result & 1) != 0;
    snprintf(app->status, STATUS_TEXT_SIZE, "MED=%d R=%c", result, app->relay_on ? '1' : '0');
    snprintf(app->info, STATUS_TEXT_SIZE, "M:%d R:%c", result, app->relay_on ? '1' : '0');
}

static void quantum_draw_callback(Canvas* canvas, void* ctx) {
    QuantumApp* app = ctx;
    if(app->help_visible) {
        quantum_draw_help(canvas);
        return;
    }

    float p[4];
    for(int i = 0; i < 4; i++) {
        p[i] = app->state[i] * app->state[i];
    }
    char line[STATUS_TEXT_SIZE];

    canvas_clear(canvas);
    canvas_draw_str_aligned(canvas, 64, 4, AlignCenter, AlignTop, "Q Sim");

    const int bar_x = 30;
    const int bar_w = 66;
    const int bar_h = 5;
    const int y0 = 12;
    for(int i = 0; i < 4; i++) {
        int y = y0 + i * 9;
        const char* lbl = (i == 0) ? "A" : (i == 1) ? "B" : (i == 2) ? "C" : "D";
        canvas_draw_str(canvas, 6, y, lbl);
        canvas_draw_frame(canvas, bar_x - 1, y - 1, bar_w + 2, bar_h + 2);
        int fill_w = (int)(p[i] * (float)(bar_w - 4) + 0.5f);
        if(fill_w > 0) {
            if(fill_w > (bar_w - 4)) fill_w = bar_w - 4;
            canvas_draw_box(canvas, bar_x + 2, y + 1, fill_w, bar_h - 2);
        }

        char pct[8];
        int perc = (int)(p[i] * 100.0f + 0.5f);
        snprintf(pct, sizeof(pct), "%3d%%", perc);
        canvas_draw_str(canvas, bar_x + bar_w + 4, y, pct);
    }

    snprintf(line, sizeof(line), "%s", app->info);
    canvas_draw_str_aligned(canvas, 64, 52, AlignCenter, AlignTop, line);
}

static void quantum_input_callback(InputEvent* event, void* ctx) {
    if(!ctx) {
        return;
    }
    FuriMessageQueue* event_queue = ctx;
    furi_message_queue_put(event_queue, event, 0);
}

int32_t quantum_simulator_app(void* p) {
    UNUSED(p);

    QuantumApp app;
    app.state[0] = 1.0f;
    app.state[1] = 0.0f;
    app.state[2] = 0.0f;
    app.state[3] = 0.0f;
    app.relay_on = false;
    app.help_visible = false;
    quantum_set_status(&app, "Pulsa direcc.");
    quantum_set_info(&app, "U:D/L/R O B");

    FuriMessageQueue* event_queue = furi_message_queue_alloc(8, sizeof(InputEvent));
    ViewPort* view_port = view_port_alloc();
    view_port_draw_callback_set(view_port, quantum_draw_callback, &app);
    view_port_input_callback_set(view_port, quantum_input_callback, event_queue);

    Gui* gui = furi_record_open(RECORD_GUI);
    gui_add_view_port(gui, view_port, GuiLayerFullscreen);

    bool running = true;
    InputEvent event;
    while(running) {
        if(furi_message_queue_get(event_queue, &event, 100) == FuriStatusOk) {
            if(event.type == InputTypeShort) {
                switch(event.key) {
                case InputKeyOk:
                    if(app.help_visible) {
                        app.help_visible = false;
                    } else {
                        quantum_apply_cnot(&app);
                    }
                    break;
                case InputKeyUp:
                    quantum_apply_h0(&app);
                    break;
                case InputKeyDown:
                    quantum_apply_h1(&app);
                    break;
                case InputKeyLeft:
                    quantum_apply_x0(&app);
                    break;
                case InputKeyRight:
                    quantum_apply_x1(&app);
                    break;
                case InputKeyBack:
                    if(app.help_visible) {
                        app.help_visible = false;
                    } else {
                        quantum_measure(&app);
                    }
                    break;
                default:
                    break;
                }
            } else if(event.type == InputTypeLong) {
                if(event.key == InputKeyOk) {
                    app.help_visible = !app.help_visible;
                    quantum_set_info(&app, app.help_visible ? "AYUDA" : "U:D/L/R O B");
                } else if(event.key == InputKeyBack) {
                    running = false;
                }
            }
        }
        view_port_update(view_port);
    }

    view_port_enabled_set(view_port, false);
    gui_remove_view_port(gui, view_port);
    view_port_free(view_port);
    furi_message_queue_free(event_queue);
    furi_record_close(RECORD_GUI);

    return 0;
}
