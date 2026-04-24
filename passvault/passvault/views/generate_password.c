#include "generate_password.h"
#include <string.h>

/* ============================================================
 *  Character sets  (matching original passgen levels)
 * ============================================================ */

#define PG_DIGITS   "0123456789"
#define PG_LOWER    "abcdefghijklmnopqrstuvwxyz"
#define PG_UPPER    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define PG_SPECIAL  "!#$%^&*.-_"

static const char* const pg_alphabets[] = {
    PG_DIGITS,
    PG_LOWER,
    PG_LOWER PG_DIGITS,
    PG_UPPER PG_LOWER PG_DIGITS,
    PG_UPPER PG_LOWER PG_DIGITS PG_SPECIAL,
};
static const char* const pg_level_names[] = {"1234", "abcd", "ab12", "Ab12", "Ab1#"};
#define PG_LEVELS 5

/* ============================================================
 *  Generator helpers
 * ============================================================ */

void pv_gen_build_alphabet(AppContext* app) {
    if(app->gen_level < 0) app->gen_level = 0;
    if(app->gen_level >= PG_LEVELS) app->gen_level = PG_LEVELS - 1;
    app->gen_alphabet = pg_alphabets[app->gen_level];
}

void pv_gen_generate(AppContext* app) {
    memset(app->generated_password, 0, GEN_MAX_LEN + 1);

    int char_count = (int)strlen(app->gen_alphabet);
    if(char_count <= 0) return;

    /* largest value without modulo bias */
    uint8_t ceil_val = (uint8_t)(255 - (255 % (unsigned)char_count) - 1);

    void*  remaining_buf = app->generated_password;
    size_t remaining_len = (size_t)app->gen_length;

    while(remaining_len > 0) {
        furi_hal_random_fill_buf(remaining_buf, remaining_len);

        uint8_t* src = remaining_buf;
        uint8_t* dst = remaining_buf;
        size_t   kept = 0;

        for(size_t i = 0; i < remaining_len; i++) {
            uint8_t v = src[i];
            if(v <= ceil_val) {
                *dst = (uint8_t)(app->gen_alphabet[v % (unsigned)char_count]);
                dst++;
                kept++;
            }
        }
        remaining_len -= kept;
        remaining_buf  = dst;
    }
}

/* ============================================================
 *  Draw
 * ============================================================ */

static void gp_draw(Canvas* canvas, void* model) {
    AppContext** m = model;
    AppContext* app = *m;

    canvas_clear(canvas);

    /* header bar */
    canvas_set_color(canvas, ColorBlack);
    canvas_draw_box(canvas, 0, 0, 128, 13);
    canvas_set_color(canvas, ColorWhite);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str_aligned(canvas, 64, 7, AlignCenter, AlignCenter,
                            "PassVault Generator");

    /* generated password */
    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str_aligned(canvas, 64, 30, AlignCenter, AlignCenter,
                            app->generated_password);

    /* bottom controls */
    char len_str[12];
    snprintf(len_str, sizeof(len_str), "Len:%d", app->gen_length);

    canvas_draw_str(canvas, 2,  60, len_str);
    canvas_draw_str(canvas, 48, 60, pg_level_names[app->gen_level]);
    canvas_draw_str(canvas, 90, 60, "LngOK=Save");
}

/* ============================================================
 *  Input
 * ============================================================ */

static bool gp_input(InputEvent* event, void* context) {
    AppContext* app = context;

    if(event->type == InputTypeShort) {
        switch(event->key) {
        case InputKeyUp:
            if(app->gen_level < PG_LEVELS - 1) {
                app->gen_level++;
                pv_gen_build_alphabet(app);
                pv_gen_generate(app);
                notification_message(app->notifications,
                                     &sequence_blink_blue_100);
            } else {
                notification_message(app->notifications,
                                     &sequence_blink_red_100);
            }
            return true;

        case InputKeyDown:
            if(app->gen_level > 0) {
                app->gen_level--;
                pv_gen_build_alphabet(app);
                pv_gen_generate(app);
                notification_message(app->notifications,
                                     &sequence_blink_blue_100);
            } else {
                notification_message(app->notifications,
                                     &sequence_blink_red_100);
            }
            return true;

        case InputKeyRight:
            if(app->gen_length < GEN_MAX_LEN) {
                app->gen_length++;
                pv_gen_generate(app);
                notification_message(app->notifications,
                                     &sequence_blink_blue_100);
            } else {
                notification_message(app->notifications,
                                     &sequence_blink_red_100);
            }
            return true;

        case InputKeyLeft:
            if(app->gen_length > 4) {
                app->gen_length--;
                pv_gen_generate(app);
                notification_message(app->notifications,
                                     &sequence_blink_blue_100);
            } else {
                notification_message(app->notifications,
                                     &sequence_blink_red_100);
            }
            return true;

        case InputKeyOk:
            /* short OK: regenerate */
            pv_gen_generate(app);
            notification_message(app->notifications, &sequence_blink_blue_100);
            return true;

        case InputKeyBack:
            return false; /* navigation callback → main menu */

        default:
            break;
        }
    } else if(event->type == InputTypeLong) {
        if(event->key == InputKeyOk) {
            /* long OK: save generated password as new credential */
            strncpy(app->tmp_password, app->generated_password,
                    FIELD_SIZE - 1);
            app->tmp_password[FIELD_SIZE - 1] = '\0';
            app->tmp_name[0]     = '\0';
            app->tmp_username[0] = '\0';
            /* re-register the text input callback so it picks up
               the pre-filled tmp_password buffer */
            text_input_set_result_callback(
                app->ti_password,
                NULL, /* keep existing callback – just reset buffer link */
                NULL, NULL, 0, false);
            view_dispatcher_switch_to_view(app->view_dispatcher,
                                           ViewTextInputCredentialName);
            return true;
        }
    }
    return false;
}

/* ============================================================
 *  Alloc
 * ============================================================ */

View* pv_generate_password_view_alloc(AppContext* app) {
    View* view = view_alloc();
    view_set_context(view, app);
    view_allocate_model(view, ViewModelTypeLockFree, sizeof(AppContext*));
    AppContext** m = view_get_model(view);
    *m = app;
    view_set_draw_callback(view, gp_draw);
    view_set_input_callback(view, gp_input);
    return view;
}
