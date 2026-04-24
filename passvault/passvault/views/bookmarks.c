#include "bookmarks.h"
#include "../passwordStorage/passwordStorage.h"

#define BKM_VISIBLE 4

/* Build a filtered list of bookmarked credential indices into out[].
   Returns the count. */
static size_t collect_bookmarks(AppContext* app,
                                size_t out[MAX_CREDENTIALS]) {
    size_t count = 0;
    for(size_t i = 0; i < app->credentials_number; i++) {
        if(app->credentials[i].bookmarked) out[count++] = i;
    }
    return count;
}

/* ============================================================
 *  Draw
 * ============================================================ */

static void bkm_draw(Canvas* canvas, void* model) {
    AppContext** m = model;
    AppContext* app = *m;

    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    canvas_set_color(canvas, ColorBlack);
    canvas_draw_str(canvas, 20, 10, "* Bookmarks");
    canvas_draw_line(canvas, 0, 12, 128, 12);

    size_t bkm_idx[MAX_CREDENTIALS];
    size_t bkm_count = collect_bookmarks(app, bkm_idx);

    if(bkm_count == 0) {
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str_aligned(canvas, 64, 36, AlignCenter, AlignCenter,
                                "No bookmarks yet");
        canvas_draw_str_aligned(canvas, 64, 50, AlignCenter, AlignCenter,
                                "Press <- in Passwords");
        return;
    }

    size_t start = app->bkm_scroll_offset;
    size_t end   = start + BKM_VISIBLE;
    if(end > bkm_count) end = bkm_count;

    for(size_t bi = start; bi < end; bi++) {
        size_t ci = bkm_idx[bi];
        int y = 25 + (int)(bi - start) * 12;

        if(bi == app->bkm_selected) {
            canvas_set_color(canvas, ColorBlack);
            canvas_draw_box(canvas, 0, y - 10, 120, 12);
            canvas_set_color(canvas, ColorWhite);
        } else {
            canvas_set_color(canvas, ColorBlack);
        }
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str(canvas, 5, y, app->credentials[ci].name);
    }

    canvas_set_color(canvas, ColorBlack);

    /* scroll bar */
    if(bkm_count > BKM_VISIBLE) {
        int bar_h = 48;
        int ind_h = bar_h * BKM_VISIBLE / (int)bkm_count;
        if(ind_h < 6) ind_h = 6;
        int scroll_range = (int)bkm_count - BKM_VISIBLE;
        int ind_y = 14 + (bar_h - ind_h) * (int)app->bkm_scroll_offset
                    / scroll_range;
        canvas_draw_box(canvas, 124, ind_y, 3, ind_h);
    }
}

/* ============================================================
 *  Input
 * ============================================================ */

static bool bkm_input(InputEvent* event, void* context) {
    AppContext* app = context;

    size_t bkm_idx[MAX_CREDENTIALS];
    size_t bkm_count = collect_bookmarks(app, bkm_idx);

    if(event->type == InputTypeShort) {
        switch(event->key) {
        case InputKeyUp:
            if(app->bkm_selected > 0) {
                app->bkm_selected--;
                if(app->bkm_selected < app->bkm_scroll_offset)
                    app->bkm_scroll_offset--;
            }
            return true;

        case InputKeyDown:
            if(app->bkm_selected + 1 < bkm_count) {
                app->bkm_selected++;
                if(app->bkm_selected >= app->bkm_scroll_offset + BKM_VISIBLE)
                    app->bkm_scroll_offset++;
            }
            return true;

        case InputKeyOk:
            if(bkm_count > 0) {
                size_t ci = bkm_idx[app->bkm_selected];
                app->detail_index  = ci;
                app->detail_origin = ViewBookmarks;
                view_dispatcher_switch_to_view(app->view_dispatcher,
                                               ViewCredentialDetail);
            }
            return true;

        case InputKeyBack:
            app->bkm_selected      = 0;
            app->bkm_scroll_offset = 0;
            return false;

        default:
            break;
        }
    }
    return false;
}

/* ============================================================
 *  Alloc
 * ============================================================ */

View* pv_bookmarks_view_alloc(AppContext* app) {
    View* view = view_alloc();
    view_set_context(view, app);
    view_allocate_model(view, ViewModelTypeLockFree, sizeof(AppContext*));
    AppContext** m = view_get_model(view);
    *m = app;
    view_set_draw_callback(view, bkm_draw);
    view_set_input_callback(view, bkm_input);
    return view;
}
