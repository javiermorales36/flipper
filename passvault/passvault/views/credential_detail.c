#include "credential_detail.h"
#include <string.h>

/*
 *  Credential detail view
 *  ─────────────────────
 *  Shows:   Service / URL  (row 0)
 *           Username       (row 1)
 *           Password       (row 2, plain text)
 *
 *  Controls:
 *    Up / Down  ── move focus between the three rows
 *    Back       ── return to previous list
 */

#define DETAIL_ROWS 3

/* which row is "focused" – stored in a tiny local model */
typedef struct {
    AppContext* app;
    int         focus;      /* 0=service, 1=username, 2=password */
} DetailModel;

/* ============================================================
 *  Draw
 * ============================================================ */

static void cd_draw(Canvas* canvas, void* raw_model) {
    DetailModel* dm  = raw_model;
    AppContext*  app = dm->app;

    if(app->detail_index >= app->credentials_number) return;
    const Credential* c = &app->credentials[app->detail_index];

    canvas_clear(canvas);

    /* ── header ── */
    canvas_set_color(canvas, ColorBlack);
    canvas_draw_box(canvas, 0, 0, 128, 13);
    canvas_set_color(canvas, ColorWhite);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str_aligned(canvas, 64, 7, AlignCenter, AlignCenter,
                            "Credential Detail");

    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontSecondary);

    /* ── row definitions ── */
    const char* labels[DETAIL_ROWS] = {"Service:", "User:", "Pass:"};
    const char* values[DETAIL_ROWS];

    values[0] = c->name;
    values[1] = strlen(c->username) > 0 ? c->username : "(none)";
    values[2] = strlen(c->password) > 0 ? c->password : "(empty)";

    for(int i = 0; i < DETAIL_ROWS; i++) {
        int y_base = 22 + i * 14;

        /* highlight focused row */
        if(i == dm->focus) {
            canvas_set_color(canvas, ColorBlack);
            canvas_draw_box(canvas, 0, y_base - 9, 128, 13);
            canvas_set_color(canvas, ColorWhite);
        } else {
            canvas_set_color(canvas, ColorBlack);
        }

        /* label (bold) */
        canvas_set_font(canvas, FontPrimary);
        canvas_draw_str(canvas, 2, y_base, labels[i]);

        /* value (secondary, truncated to fit) */
        canvas_set_font(canvas, FontSecondary);
        /* label widths: "Service:" ~48px, "User:" ~32px, "Pass:" ~30px */
        int label_w = (i == 0) ? 50 : (i == 1) ? 34 : 32;
        canvas_draw_str(canvas, label_w, y_base, values[i]);
    }

    /* ── hint ── */
    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str_aligned(canvas, 64, 60, AlignCenter, AlignCenter,
                            "\x18\x19 navigate  Back return");
}

/* ============================================================
 *  Input
 * ============================================================ */

static bool cd_input(InputEvent* event, void* raw_model) {
    DetailModel* dm  = raw_model;
    UNUSED(dm->app);

    if(event->type == InputTypeShort) {
        switch(event->key) {
        case InputKeyUp:
            if(dm->focus > 0) dm->focus--;
            return true;

        case InputKeyDown:
            if(dm->focus < DETAIL_ROWS - 1) dm->focus++;
            return true;

        case InputKeyOk:
            return true;

        case InputKeyBack:
            /* reset for next time */
            dm->focus = 0;
            return false; /* navigation callback → list */

        default:
            break;
        }
    }
    return false;
}

/* ============================================================
 *  Alloc
 * ============================================================ */

View* pv_credential_detail_view_alloc(AppContext* app) {
    View* view = view_alloc();
    view_set_context(view, app);
    view_allocate_model(view, ViewModelTypeLockFree, sizeof(DetailModel));
    DetailModel* dm = view_get_model(view);
    dm->app   = app;
    dm->focus = 0;
    view_set_draw_callback(view, cd_draw);
    view_set_input_callback(view, cd_input);
    return view;
}
