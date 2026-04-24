#include "pin_view.h"
#include "../passwordStorage/passwordStorage.h"

/* ============================================================
 *  Draw
 * ============================================================
 *
 *  Layout (128 x 64 pixels):
 *   Line 0..11  : header
 *   Line 14     : separator
 *   Line 22..45 : four digit boxes (20x20 px each, gap 6 px)
 *   Line 52..63 : hint text
 */

#define BOX_SIZE 20
#define BOX_GAP  6
/* 4 boxes: 4*20 + 3*6 = 98 px wide; start x = (128-98)/2 = 15 */
#define BOX_START_X 15
#define BOX_Y       22

static void pin_draw(Canvas* canvas, void* model) {
    AppContext** m = model;
    AppContext* app = *m;

    canvas_clear(canvas);

    /* header */
    canvas_set_font(canvas, FontPrimary);
    canvas_set_color(canvas, ColorBlack);
    if(app->setting_pin) {
        canvas_draw_str_aligned(canvas, 64, 8, AlignCenter, AlignCenter,
                                "Set New PIN");
    } else {
        canvas_draw_str_aligned(canvas, 64, 8, AlignCenter, AlignCenter,
                                "Enter PIN");
    }
    canvas_draw_line(canvas, 0, 14, 128, 14);

    /* four digit boxes */
    for(int i = 0; i < PIN_LENGTH; i++) {
        int x = BOX_START_X + i * (BOX_SIZE + BOX_GAP);

        if(i == app->pin_cursor) {
            /* selected box: filled black, white digit */
            canvas_set_color(canvas, ColorBlack);
            canvas_draw_box(canvas, x, BOX_Y, BOX_SIZE, BOX_SIZE);
            canvas_set_color(canvas, ColorWhite);
        } else {
            /* unselected: outlined */
            canvas_set_color(canvas, ColorBlack);
            canvas_draw_frame(canvas, x, BOX_Y, BOX_SIZE, BOX_SIZE);
        }

        char s[2] = {app->pin_input[i], '\0'};
        canvas_set_font(canvas, FontPrimary);
        canvas_draw_str_aligned(canvas, x + BOX_SIZE / 2,
                                BOX_Y + BOX_SIZE / 2,
                                AlignCenter, AlignCenter, s);
    }

    /* hint */
    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str_aligned(canvas, 64, 58, AlignCenter, AlignCenter,
                            "\x18\x19 digit  \x1a\x1b move  OK confirm");
}

/* ============================================================
 *  Input
 * ============================================================ */

static bool pin_input(InputEvent* event, void* context) {
    AppContext* app = context;

    if(event->type != InputTypeShort) return false;

    switch(event->key) {
    /* ---- change active digit value ---- */
    case InputKeyUp:
        app->pin_input[app->pin_cursor] =
            (app->pin_input[app->pin_cursor] < '9')
                ? app->pin_input[app->pin_cursor] + 1
                : '0';
        return true;

    case InputKeyDown:
        app->pin_input[app->pin_cursor] =
            (app->pin_input[app->pin_cursor] > '0')
                ? app->pin_input[app->pin_cursor] - 1
                : '9';
        return true;

    /* ---- move cursor ---- */
    case InputKeyRight:
        if(app->pin_cursor < PIN_LENGTH - 1) app->pin_cursor++;
        return true;

    case InputKeyLeft:
        if(app->pin_cursor > 0) app->pin_cursor--;
        return true;

    /* ---- back: cancel ---- */
    case InputKeyBack:
        /* reset the input buffer */
        memset(app->pin_input, '0', PIN_LENGTH);
        app->pin_input[PIN_LENGTH] = '\0';
        app->pin_cursor = 0;

        if(app->setting_pin) {
            /* return to main menu (user cancelled change-PIN) */
            view_dispatcher_switch_to_view(app->view_dispatcher, ViewMainMenu);
        } else {
            /* user cancelled unlock – exit the whole app */
            app->running = false;
            view_dispatcher_stop(app->view_dispatcher);
        }
        return true;

    /* ---- confirm ---- */
    case InputKeyOk:
        app->pin_input[PIN_LENGTH] = '\0';

        if(app->setting_pin) {
            /* save the new PIN */
            memcpy(app->pin, app->pin_input, PIN_LENGTH + 1);
            pv_save_pin(app->pin);
            app->pin_set    = true;
            app->setting_pin = false;
            /* reset entry buffer for next time */
            memset(app->pin_input, '0', PIN_LENGTH);
            app->pin_input[PIN_LENGTH] = '\0';
            app->pin_cursor = 0;
            view_dispatcher_switch_to_view(app->view_dispatcher, ViewMainMenu);
        } else {
            /* verify PIN */
            if(memcmp(app->pin_input, app->pin, PIN_LENGTH) == 0) {
                memset(app->pin_input, '0', PIN_LENGTH);
                app->pin_input[PIN_LENGTH] = '\0';
                app->pin_cursor = 0;
                view_dispatcher_switch_to_view(app->view_dispatcher,
                                               ViewMainMenu);
            } else {
                /* wrong PIN: red blink and reset digits */
                notification_message(app->notifications,
                                     &sequence_blink_red_100);
                memset(app->pin_input, '0', PIN_LENGTH);
                app->pin_input[PIN_LENGTH] = '\0';
                app->pin_cursor = 0;
            }
        }
        return true;

    default:
        break;
    }
    return false;
}

/* ============================================================
 *  Alloc
 * ============================================================ */

View* pv_pin_view_alloc(AppContext* app) {
    View* view = view_alloc();
    view_set_context(view, app);
    view_allocate_model(view, ViewModelTypeLockFree, sizeof(AppContext*));
    AppContext** m = view_get_model(view);
    *m = app;
    view_set_draw_callback(view, pin_draw);
    view_set_input_callback(view, pin_input);
    return view;
}
