#include "import_result.h"
#include "../passwordStorage/passwordStorage.h"

static void ir_draw(Canvas* canvas, void* model) {
    AppContext** m = model;
    AppContext* app = *m;

    canvas_clear(canvas);

    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str_aligned(canvas, 64, 8, AlignCenter, AlignCenter,
                            "Import CSV");
    canvas_draw_line(canvas, 0, 14, 128, 14);

    canvas_set_font(canvas, FontSecondary);

    if(app->import_error) {
        canvas_draw_str_aligned(canvas, 64, 28, AlignCenter, AlignCenter,
                                "File not found!");
        canvas_draw_str_aligned(canvas, 64, 40, AlignCenter, AlignCenter,
                                "Place file at:");
        canvas_draw_str_aligned(canvas, 64, 50, AlignCenter, AlignCenter,
                                "/ext/passvault/import.csv");
    } else {
        char msg[40];
        snprintf(msg, sizeof(msg), "Imported: %u new entries",
                 (unsigned)app->import_count);
        canvas_draw_str_aligned(canvas, 64, 32, AlignCenter, AlignCenter, msg);

        if(app->import_count == 0) {
            canvas_draw_str_aligned(canvas, 64, 44, AlignCenter, AlignCenter,
                                    "(all already existed)");
        }
    }

    canvas_draw_str_aligned(canvas, 64, 60, AlignCenter, AlignCenter,
                            "Press any key");
}

static bool ir_input(InputEvent* event, void* context) {
    AppContext* app = context;
    if(event->type == InputTypeShort) {
        /* reload credentials so list is up to date */
        app->credentials_number =
            pv_read_credentials(app->credentials, MAX_CREDENTIALS);
        pv_load_bookmarks(app->credentials, app->credentials_number);
        app->selected      = 0;
        app->scroll_offset = 0;
        view_dispatcher_switch_to_view(app->view_dispatcher, ViewMainMenu);
        return true;
    }
    return false;
}

View* pv_import_result_view_alloc(AppContext* app) {
    View* view = view_alloc();
    view_set_context(view, app);
    view_allocate_model(view, ViewModelTypeLockFree, sizeof(AppContext*));
    AppContext** m = view_get_model(view);
    *m = app;
    view_set_draw_callback(view, ir_draw);
    view_set_input_callback(view, ir_input);
    return view;
}
