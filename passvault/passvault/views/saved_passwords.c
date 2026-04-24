#include "saved_passwords.h"
#include "../passwordStorage/passwordStorage.h"

#define MAX_VISIBLE 4

/* ============================================================
 *  Draw
 * ============================================================ */

static void sp_draw(Canvas* canvas, void* model) {
    AppContext** m = model;
    AppContext* app = *m;

    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    canvas_set_color(canvas, ColorBlack);
    canvas_draw_str(canvas, 2, 10, "Saved Passwords");
    canvas_draw_line(canvas, 0, 12, 128, 12);

    if(app->credentials_number == 0) {
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str_aligned(canvas, 64, 36, AlignCenter, AlignCenter,
                                "No credentials saved");
        return;
    }

    size_t start = app->scroll_offset;
    size_t end   = start + MAX_VISIBLE;
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

        /* bookmark star prefix */
        char label[FIELD_SIZE + 2];
        if(app->credentials[i].bookmarked) {
            label[0] = '*';
            strncpy(label + 1, app->credentials[i].name, FIELD_SIZE - 1);
            label[FIELD_SIZE] = '\0';
        } else {
            strncpy(label, app->credentials[i].name, FIELD_SIZE - 1);
            label[FIELD_SIZE - 1] = '\0';
        }
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str(canvas, 5, y, label);
    }

    canvas_set_color(canvas, ColorBlack);

    /* scroll bar */
    if(app->credentials_number > MAX_VISIBLE) {
        int bar_h = 48;
        int ind_h = bar_h * MAX_VISIBLE / (int)app->credentials_number;
        if(ind_h < 6) ind_h = 6;
        int scroll_range = (int)app->credentials_number - MAX_VISIBLE;
        int ind_y = 14 + (bar_h - ind_h) * (int)app->scroll_offset / scroll_range;
        canvas_draw_box(canvas, 124, ind_y, 3, ind_h);
    }

    /* hint at bottom: left = toggle bookmark */
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str(canvas, 0, 63, "\x1a bkm  OK view");
}

/* ============================================================
 *  Input
 * ============================================================ */

static bool sp_input(InputEvent* event, void* context) {
    AppContext* app = context;

    if(event->type == InputTypeShort) {
        switch(event->key) {
        case InputKeyUp:
            if(app->selected > 0) {
                app->selected--;
                if(app->selected < app->scroll_offset)
                    app->scroll_offset--;
            }
            return true;

        case InputKeyDown:
            if(app->selected + 1 < app->credentials_number) {
                app->selected++;
                if(app->selected >= app->scroll_offset + MAX_VISIBLE)
                    app->scroll_offset++;
            }
            return true;

        case InputKeyLeft:
            /* toggle bookmark */
            if(app->credentials_number > 0) {
                app->credentials[app->selected].bookmarked =
                    !app->credentials[app->selected].bookmarked;
                pv_save_bookmarks(app->credentials, app->credentials_number);
            }
            return true;

        case InputKeyOk:
            /* open credential detail view */
            if(app->credentials_number > 0) {
                app->detail_index  = app->selected;
                app->detail_origin = ViewSavedPasswords;
                view_dispatcher_switch_to_view(app->view_dispatcher,
                                               ViewCredentialDetail);
            }
            return true;

        case InputKeyBack:
            app->selected      = 0;
            app->scroll_offset = 0;
            return false; /* let navigation callback handle it */

        default:
            break;
        }
    }
    return false;
}

/* ============================================================
 *  Alloc
 * ============================================================ */

View* pv_saved_passwords_view_alloc(AppContext* app) {
    View* view = view_alloc();
    view_set_context(view, app);
    view_allocate_model(view, ViewModelTypeLockFree, sizeof(AppContext*));
    AppContext** m = view_get_model(view);
    *m = app;
    view_set_draw_callback(view, sp_draw);
    view_set_input_callback(view, sp_input);
    return view;
}
