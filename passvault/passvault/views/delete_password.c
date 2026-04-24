#include "delete_password.h"
#include "../passwordStorage/passwordStorage.h"

#define DEL_VISIBLE 4

/* ============================================================
 *  Draw
 * ============================================================ */

static void dp_draw(Canvas* canvas, void* model) {
    AppContext** m = model;
    AppContext* app = *m;

    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    canvas_set_color(canvas, ColorBlack);
    canvas_draw_str(canvas, 4, 10, "Delete Password");
    canvas_draw_line(canvas, 0, 12, 128, 12);

    if(app->credentials_number == 0) {
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str_aligned(canvas, 64, 36, AlignCenter, AlignCenter,
                                "No credentials saved");
        return;
    }

    size_t start = app->scroll_offset;
    size_t end   = start + DEL_VISIBLE;
    if(end > app->credentials_number) end = app->credentials_number;

    for(size_t i = start; i < end; i++) {
        int y = 25 + (int)(i - start) * 12;

        if(i == app->selected) {
            canvas_set_color(canvas, ColorBlack);
            canvas_draw_box(canvas, 0, y - 10, 120, 12);
            canvas_set_color(canvas, ColorWhite);
        } else {
            canvas_set_color(canvas, ColorBlack);
        }
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str(canvas, 5, y, app->credentials[i].name);
    }

    canvas_set_color(canvas, ColorBlack);

    /* scroll bar */
    if(app->credentials_number > DEL_VISIBLE) {
        int bar_h = 48;
        int ind_h = bar_h * DEL_VISIBLE / (int)app->credentials_number;
        if(ind_h < 6) ind_h = 6;
        int scroll_range = (int)app->credentials_number - DEL_VISIBLE;
        int ind_y = 14 + (bar_h - ind_h) * (int)app->scroll_offset / scroll_range;
        canvas_draw_box(canvas, 124, ind_y, 3, ind_h);
    }

    /* confirmation overlay */
    if(app->confirm_delete) {
        canvas_set_color(canvas, ColorWhite);
        canvas_draw_box(canvas, 6, 18, 116, 38);
        canvas_set_color(canvas, ColorBlack);
        canvas_draw_frame(canvas, 6, 18, 116, 38);

        char msg[FIELD_SIZE + 12];
        snprintf(msg, sizeof(msg), "Delete \"%s\"?",
                 app->credentials[app->selected].name);
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str_aligned(canvas, 64, 30, AlignCenter, AlignCenter, msg);
        canvas_draw_str_aligned(canvas, 64, 46, AlignCenter, AlignCenter,
                                "[OK] Yes   [Back] No");
    }
}

/* ============================================================
 *  Input
 * ============================================================ */

static bool dp_input(InputEvent* event, void* context) {
    AppContext* app = context;

    if(event->type != InputTypeShort) return false;

    /* ---- confirmation dialog active ---- */
    if(app->confirm_delete) {
        if(event->key == InputKeyOk) {
            pv_delete_credential(app->selected);

            /* remove from in-memory list */
            for(size_t i = app->selected;
                i + 1 < app->credentials_number; i++) {
                app->credentials[i] = app->credentials[i + 1];
            }
            app->credentials_number--;
            if(app->selected >= app->credentials_number && app->selected > 0)
                app->selected--;
            if(app->scroll_offset > app->selected)
                app->scroll_offset = app->selected;

            app->confirm_delete = false;
            view_dispatcher_switch_to_view(app->view_dispatcher, ViewMainMenu);
            return true;
        }
        if(event->key == InputKeyBack) {
            app->confirm_delete = false;
            return true;
        }
        return false;
    }

    /* ---- normal navigation ---- */
    switch(event->key) {
    case InputKeyUp:
        if(app->selected > 0) {
            app->selected--;
            if(app->selected < app->scroll_offset) app->scroll_offset--;
        }
        return true;

    case InputKeyDown:
        if(app->selected + 1 < app->credentials_number) {
            app->selected++;
            if(app->selected >= app->scroll_offset + DEL_VISIBLE)
                app->scroll_offset++;
        }
        return true;

    case InputKeyOk:
        if(app->credentials_number > 0)
            app->confirm_delete = true;
        return true;

    case InputKeyBack:
        app->selected      = 0;
        app->scroll_offset = 0;
        app->confirm_delete = false;
        return false;

    default:
        break;
    }
    return false;
}

/* ============================================================
 *  Alloc
 * ============================================================ */

View* pv_delete_password_view_alloc(AppContext* app) {
    View* view = view_alloc();
    view_set_context(view, app);
    view_allocate_model(view, ViewModelTypeLockFree, sizeof(AppContext*));
    AppContext** m = view_get_model(view);
    *m = app;
    view_set_draw_callback(view, dp_draw);
    view_set_input_callback(view, dp_input);
    return view;
}
