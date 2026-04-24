// TOTP Vault — Hardware TOTP authenticator for Flipper Zero
// Javier Morales — 2026
// Vault: AES-256-CTR + HMAC-SHA256 | KDF: PBKDF2-HMAC-SHA256 (10k iter)
// TOTP: RFC 6238 + HMAC-SHA1 | Import: /ext/totp_vault/import.txt

#include <furi.h>
#include <furi_hal_rtc.h>
#include <furi_hal_random.h>
#include <gui/gui.h>
#include <gui/elements.h>
#include <input/input.h>

#include "lib/totp/totp_store.h"
#include "lib/totp/totp.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// ─── Constantes de UI ───────────────────────────────────────────────────────
#define LIST_VISIBLE_ROWS 4
#define PIN_LEN           4

// ─── Tipos de evento ─────────────────────────────────────────────────────────
typedef enum {
    EvtInput,
    EvtTimer,
} EvtType;

typedef struct {
    EvtType    type;
    InputEvent input;
} AppEvent;

// ─── Pantallas ───────────────────────────────────────────────────────────────
typedef enum {
    ScreenPin,
    ScreenList,
    ScreenCode,
} Screen;

// ─── Estado de la aplicación ─────────────────────────────────────────────────
typedef struct {
    Gui*              gui;
    ViewPort*         vp;
    FuriMessageQueue* queue;
    FuriMutex*        mutex;
    FuriTimer*        timer;
    bool              running;

    // Pantalla activa
    Screen screen;
    char   status[48]; // mensaje de estado/error bajo la entrada de PIN

    // Entrada de PIN
    uint8_t pin_digits[PIN_LEN]; // 0..9
    uint8_t pin_pos;             // 0..3 (dígito activo)
    char    pin_str[PIN_LEN + 1];

    // Cuentas (tras desbloqueo)
    TotpAccount accounts[TOTP_MAX_ACCOUNTS];
    uint8_t     account_count;
    uint8_t     list_idx;   // índice seleccionado
    uint8_t     list_top;   // primer índice visible

    // Vista de código
    char     code_str[7];  // "123456"
    uint64_t code_period;  // timestamp/30 cuando se calculó el código
} TotpVaultApp;

// ─── Dibujo: pantalla PIN ─────────────────────────────────────────────────────
static void draw_pin(Canvas* c, TotpVaultApp* app) {
    canvas_set_font(c, FontPrimary);
    canvas_draw_str_aligned(c, 64, 4, AlignCenter, AlignTop, "TOTP Vault");

    // 4 cajas de dígito centradas: cada caja 16×20px, gap 4px
    // total=4*16+3*4=76; start_x=(128-76)/2=26
    for(int i = 0; i < PIN_LEN; i++) {
        int x = 26 + i * 20;
        int y = 20;
        if(i == (int)app->pin_pos) {
            canvas_draw_rbox(c, x, y, 16, 20, 3);
            canvas_set_color(c, ColorWhite);
        } else {
            canvas_draw_rframe(c, x, y, 16, 20, 3);
            canvas_set_color(c, ColorBlack);
        }
        char ch[2] = {(char)('0' + app->pin_digits[i]), '\0'};
        canvas_set_font(c, FontPrimary);
        canvas_draw_str_aligned(c, x + 8, y + 4, AlignCenter, AlignTop, ch);
        canvas_set_color(c, ColorBlack);
    }

    canvas_set_font(c, FontSecondary);
    if(app->status[0]) {
        canvas_draw_str_aligned(c, 64, 44, AlignCenter, AlignTop, app->status);
    } else {
        canvas_draw_str_aligned(c, 64, 44, AlignCenter, AlignTop, "UP/DN digito  -> sig  OK entrar");
    }
    canvas_draw_str_aligned(c, 64, 55, AlignCenter, AlignTop, "Back: salir");
}

// ─── Dibujo: lista de cuentas ─────────────────────────────────────────────────
static void draw_list(Canvas* c, TotpVaultApp* app) {
    canvas_set_font(c, FontPrimary);
    canvas_draw_str_aligned(c, 64, 0, AlignCenter, AlignTop, "TOTP Vault");
    canvas_draw_line(c, 0, 12, 128, 12);

    if(app->account_count == 0) {
        canvas_set_font(c, FontSecondary);
        canvas_draw_str_aligned(c, 64, 24, AlignCenter, AlignTop, "Sin cuentas");
        canvas_draw_str_aligned(c, 64, 36, AlignCenter, AlignTop, "Crea import.txt en SD");
        return;
    }

    canvas_set_font(c, FontSecondary);
    for(uint8_t i = 0; i < LIST_VISIBLE_ROWS && (app->list_top + i) < app->account_count; i++) {
        uint8_t idx = app->list_top + i;
        int     y   = 14 + i * 12;
        if(idx == app->list_idx) {
            canvas_draw_box(c, 0, y - 1, 128, 11);
            canvas_set_color(c, ColorWhite);
        }
        canvas_draw_str(c, 4, y + 8, app->accounts[idx].name);
        canvas_set_color(c, ColorBlack);
    }

    // Barra de scroll
    if(app->account_count > LIST_VISIBLE_ROWS) {
        int bar_h = 48 * LIST_VISIBLE_ROWS / app->account_count;
        int bar_y = 14 + 48 * app->list_top / app->account_count;
        canvas_draw_box(c, 125, bar_y, 3, bar_h);
    }
}

// ─── Dibujo: código TOTP ──────────────────────────────────────────────────────
static void draw_code(Canvas* c, TotpVaultApp* app) {
    TotpAccount* acc = &app->accounts[app->list_idx];

    canvas_set_font(c, FontSecondary);
    canvas_draw_str_aligned(c, 64, 1, AlignCenter, AlignTop, acc->name);

    // "NNN NNN" en fuente grande
    char display[8];
    display[0] = app->code_str[0];
    display[1] = app->code_str[1];
    display[2] = app->code_str[2];
    display[3] = ' ';
    display[4] = app->code_str[3];
    display[5] = app->code_str[4];
    display[6] = app->code_str[5];
    display[7] = '\0';

    canvas_set_font(c, FontBigNumbers);
    canvas_draw_str_aligned(c, 64, 14, AlignCenter, AlignTop, display);

    // Barra de cuenta regresiva
    uint32_t now     = furi_hal_rtc_get_timestamp();
    uint32_t elapsed = now % (uint32_t)acc->period;
    uint32_t remain  = (uint32_t)acc->period - elapsed;
    int      bar_w   = (int)(128u * remain / (uint32_t)acc->period);

    canvas_draw_rframe(c, 0, 52, 128, 9, 2);
    if(bar_w > 0) canvas_draw_rbox(c, 0, 52, bar_w, 9, 2);

    char rem_str[8];
    snprintf(rem_str, sizeof(rem_str), "%us", (unsigned)remain);
    canvas_set_color(c, (bar_w > 30) ? ColorWhite : ColorBlack);
    canvas_set_font(c, FontSecondary);
    canvas_draw_str_aligned(c, 64, 53, AlignCenter, AlignTop, rem_str);
    canvas_set_color(c, ColorBlack);
}

// ─── Callbacks ───────────────────────────────────────────────────────────────
static void draw_callback(Canvas* canvas, void* ctx) {
    TotpVaultApp* app = ctx;
    furi_mutex_acquire(app->mutex, FuriWaitForever);
    canvas_clear(canvas);
    switch(app->screen) {
    case ScreenPin:  draw_pin(canvas, app);  break;
    case ScreenList: draw_list(canvas, app); break;
    case ScreenCode: draw_code(canvas, app); break;
    }
    furi_mutex_release(app->mutex);
}

static void input_callback(InputEvent* event, void* ctx) {
    TotpVaultApp* app = ctx;
    AppEvent ev       = {.type = EvtInput, .input = *event};
    furi_message_queue_put(app->queue, &ev, 0);
}

static void timer_callback(void* ctx) {
    TotpVaultApp* app = ctx;
    AppEvent ev       = {.type = EvtTimer};
    furi_message_queue_put(app->queue, &ev, 0);
}

// ─── Lógica de desbloqueo ────────────────────────────────────────────────────
static void try_unlock(TotpVaultApp* app) {
    for(int i = 0; i < PIN_LEN; i++) app->pin_str[i] = (char)('0' + app->pin_digits[i]);
    app->pin_str[PIN_LEN] = '\0';

    TotpStoreResult res = totp_store_load(app->pin_str, app->accounts, &app->account_count);

    if(res == TotpStoreOk) {
        app->status[0] = '\0';
        app->list_idx  = 0;
        app->list_top  = 0;
        app->screen    = ScreenList;

    } else if(res == TotpStoreErrNoFile) {
        // Primera vez: importar desde import.txt y guardar vault
        res = totp_store_import(app->accounts, &app->account_count);
        if(res == TotpStoreOk) {
            totp_store_save(app->pin_str, app->accounts, app->account_count);
            app->list_idx  = 0;
            app->list_top  = 0;
            app->screen    = ScreenList;
            app->status[0] = '\0';
        } else {
            snprintf(app->status, sizeof(app->status), "Crea import.txt en /ext/totp_vault/");
        }

    } else if(res == TotpStoreErrBadPin) {
        snprintf(app->status, sizeof(app->status), "PIN incorrecto");
        memset(app->pin_digits, 0, sizeof(app->pin_digits));
        app->pin_pos = 0;

    } else {
        snprintf(app->status, sizeof(app->status), "Error al leer vault");
        memset(app->pin_digits, 0, sizeof(app->pin_digits));
        app->pin_pos = 0;
    }
}

// ─── Actualizar código si el periodo cambió ──────────────────────────────────
static void refresh_code(TotpVaultApp* app) {
    if(app->account_count == 0) return;
    TotpAccount* acc = &app->accounts[app->list_idx];
    uint32_t now     = furi_hal_rtc_get_timestamp();
    uint64_t period  = now / (uint32_t)acc->period;
    if(period != app->code_period) {
        app->code_period = period;
        uint32_t code    = totp_generate(acc->secret, acc->secret_len, now, acc->period);
        totp_format(code, app->code_str);
    }
}

// ─── Manejadores de input por pantalla ───────────────────────────────────────
static void handle_pin_input(TotpVaultApp* app, InputEvent* ev) {
    if(ev->type != InputTypeShort && ev->type != InputTypeRepeat) return;
    switch(ev->key) {
    case InputKeyUp:
        app->pin_digits[app->pin_pos] = (app->pin_digits[app->pin_pos] + 1) % 10;
        break;
    case InputKeyDown:
        app->pin_digits[app->pin_pos] = (app->pin_digits[app->pin_pos] + 9) % 10;
        break;
    case InputKeyRight:
    case InputKeyOk:
        if(ev->type == InputTypeShort) {
            if(app->pin_pos < PIN_LEN - 1) {
                app->pin_pos++;
            } else {
                try_unlock(app);
            }
        }
        break;
    case InputKeyLeft:
        if(app->pin_pos > 0) app->pin_pos--;
        break;
    case InputKeyBack:
        app->running = false;
        break;
    default:
        break;
    }
}

static void handle_list_input(TotpVaultApp* app, InputEvent* ev) {
    if(ev->type != InputTypeShort && ev->type != InputTypeRepeat) return;
    switch(ev->key) {
    case InputKeyUp:
        if(app->list_idx > 0) {
            app->list_idx--;
            if(app->list_idx < app->list_top) app->list_top = app->list_idx;
        }
        break;
    case InputKeyDown:
        if(app->list_idx + 1 < app->account_count) {
            app->list_idx++;
            if(app->list_idx >= app->list_top + LIST_VISIBLE_ROWS)
                app->list_top = app->list_idx - LIST_VISIBLE_ROWS + 1;
        }
        break;
    case InputKeyOk:
        if(ev->type == InputTypeShort && app->account_count > 0) {
            app->code_period = 0; // forzar recálculo inmediato
            refresh_code(app);
            app->screen = ScreenCode;
        }
        break;
    case InputKeyBack:
        // Re-bloquear: volver a PIN
        memset(app->pin_digits, 0, sizeof(app->pin_digits));
        app->pin_pos    = 0;
        app->status[0]  = '\0';
        app->screen     = ScreenPin;
        break;
    default:
        break;
    }
}

static void handle_code_input(TotpVaultApp* app, InputEvent* ev) {
    if(ev->type != InputTypeShort) return;
    if(ev->key == InputKeyBack) app->screen = ScreenList;
}

// ─── Entry point ─────────────────────────────────────────────────────────────
int32_t totp_vault_app(void* p) {
    UNUSED(p);

    TotpVaultApp* app = malloc(sizeof(TotpVaultApp));
    if(!app) return -1;
    memset(app, 0, sizeof(TotpVaultApp));
    app->running = true;
    app->screen  = ScreenPin;

    app->mutex = furi_mutex_alloc(FuriMutexTypeNormal);
    app->queue = furi_message_queue_alloc(8, sizeof(AppEvent));
    app->vp    = view_port_alloc();

    view_port_draw_callback_set(app->vp,  draw_callback,  app);
    view_port_input_callback_set(app->vp, input_callback, app);

    app->gui = furi_record_open(RECORD_GUI);
    gui_add_view_port(app->gui, app->vp, GuiLayerFullscreen);

    app->timer = furi_timer_alloc(timer_callback, FuriTimerTypePeriodic, app);
    furi_timer_start(app->timer, 1000);

    // ─── Event loop ──────────────────────────────────────────────────────────
    AppEvent ev;
    while(app->running) {
        if(furi_message_queue_get(app->queue, &ev, 100) == FuriStatusOk) {
            furi_mutex_acquire(app->mutex, FuriWaitForever);
            if(ev.type == EvtInput) {
                switch(app->screen) {
                case ScreenPin:  handle_pin_input(app,  &ev.input); break;
                case ScreenList: handle_list_input(app, &ev.input); break;
                case ScreenCode: handle_code_input(app, &ev.input); break;
                }
            } else if(ev.type == EvtTimer && app->screen == ScreenCode) {
                refresh_code(app);
            }
            furi_mutex_release(app->mutex);
            view_port_update(app->vp);
        }
    }

    // ─── Cleanup ─────────────────────────────────────────────────────────────
    furi_timer_stop(app->timer);
    furi_timer_free(app->timer);
    gui_remove_view_port(app->gui, app->vp);
    furi_record_close(RECORD_GUI);
    view_port_free(app->vp);
    furi_message_queue_free(app->queue);
    furi_mutex_free(app->mutex);

    // Limpiar material sensible de memoria
    memset(app->pin_str,    0, sizeof(app->pin_str));
    memset(app->pin_digits, 0, sizeof(app->pin_digits));
    memset(app->accounts,   0, sizeof(app->accounts));
    free(app);
    return 0;
}
