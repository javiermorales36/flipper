#include <furi.h>
#include <gui/gui.h>
#include <gui/elements.h>
#include <input/input.h>
#include <furi_hal.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "lib/klocker/kl_store.h"
#include "lib/monocypher/monocypher.h"

// ─── Pantallas ────────────────────────────────────────────────────────────────
typedef enum {
    ScreenPin = 0,
    ScreenMenu,
    ScreenList,    // lista entries del tipo seleccionado
    ScreenDetail,  // detalle de una entry (nombre + hex de pk o password)
    ScreenGenMenu, // submenu: generar Ed25519 / X25519 / Password
    ScreenResult,  // resultado de generación (seed / sk hex)
} Screen;

// ─── Eventos ──────────────────────────────────────────────────────────────────
typedef enum { EvtInput, EvtDraw } EvtType;
typedef struct {
    EvtType   type;
    InputEvent input;
} KlEvent;

// ─── Estado global ────────────────────────────────────────────────────────────
#define PIN_LEN 4
#define MENU_ITEMS 3
static const char* MENU_LABELS[] = { "Passwords", "Keys", "Generate" };
static const char* GENMENU_LABELS[] = { "Ed25519", "X25519", "Password" };

typedef struct {
    // PIN
    uint8_t pin_digits[PIN_LEN];
    uint8_t pin_cursor;
    char    pin_str[PIN_LEN + 1];

    // Vault
    KlEntry  entries[KL_MAX_ENTRIES];
    uint8_t  entry_count;

    // Navegación
    Screen   screen;
    uint8_t  menu_sel;    // selección en ScreenMenu
    uint8_t  list_sel;    // selección en ScreenList
    uint8_t  gmenu_sel;   // selección en ScreenGenMenu
    KlEntryType list_type; // tipo mostrando en ScreenList

    // Resultado generación (hex string)
    char     result_buf[200];
    char     result_label[48];

    // Error / status
    char     status[40];

    // UI
    FuriMutex*        mutex;
    FuriMessageQueue* queue;
    ViewPort*         vp;
    Gui*              gui;
} KlApp;

// ─── Utilidades ───────────────────────────────────────────────────────────────
static void bytes_to_hex(const uint8_t* b, size_t len, char* out, size_t out_len) {
    size_t pos = 0;
    for(size_t i = 0; i < len && pos + 3 < out_len; i++, pos += 2)
        snprintf(out + pos, 3, "%02x", b[i]);
    out[pos] = '\0';
}

// Obtener índice de entries que coincidan con un tipo
static uint8_t list_filtered(KlApp* app, KlEntryType type, uint8_t out[KL_MAX_ENTRIES]) {
    uint8_t n = 0;
    for(uint8_t i = 0; i < app->entry_count; i++) {
        if(app->entries[i].type == type) out[n++] = i;
    }
    return n;
}

// ─── Render ───────────────────────────────────────────────────────────────────
static void draw_cb(Canvas* canvas, void* ctx) {
    KlApp* app = ctx;
    furi_mutex_acquire(app->mutex, FuriWaitForever);
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);

    switch(app->screen) {
    case ScreenPin: {
        canvas_draw_str(canvas, 0, 10, "Key Locker");
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str(canvas, 0, 24, "PIN:");
        // Mostrar dígitos: rellenados = número, cursor = _
        for(uint8_t i = 0; i < PIN_LEN; i++) {
            char buf[4];
            if(i < app->pin_cursor)
                snprintf(buf, sizeof(buf), "%u", app->pin_digits[i]);
            else if(i == app->pin_cursor)
                snprintf(buf, sizeof(buf), "_");
            else
                snprintf(buf, sizeof(buf), "-");
            canvas_draw_str(canvas, 40 + i * 16, 24, buf);
        }
        if(app->status[0])
            canvas_draw_str(canvas, 0, 36, app->status);
        canvas_draw_str(canvas, 0, 62, "UP/DN:digit  OK:next");
        break;
    }
    case ScreenMenu: {
        canvas_draw_str(canvas, 0, 10, "Key Locker");
        canvas_set_font(canvas, FontSecondary);
        for(uint8_t i = 0; i < MENU_ITEMS; i++) {
            if(i == app->menu_sel) canvas_draw_box(canvas, 0, 14 + i * 14, 128, 13);
            canvas_set_color(canvas, i == app->menu_sel ? ColorWhite : ColorBlack);
            canvas_draw_str(canvas, 4, 24 + i * 14, MENU_LABELS[i]);
            canvas_set_color(canvas, ColorBlack);
        }
        break;
    }
    case ScreenList: {
        uint8_t  idx[KL_MAX_ENTRIES];
        uint8_t  n = list_filtered(app, app->list_type, idx);
        const char* title = (app->list_type == KlTypePassword) ? "Passwords" : "Keys";
        canvas_draw_str(canvas, 0, 10, title);
        canvas_set_font(canvas, FontSecondary);
        if(n == 0) {
            canvas_draw_str(canvas, 0, 30, "(empty)");
        } else {
            // 3 filas visibles
            uint8_t start = (app->list_sel >= 3) ? app->list_sel - 2 : 0;
            for(uint8_t r = 0; r < 3 && (start + r) < n; r++) {
                uint8_t ei = idx[start + r];
                const char* nm = (app->entries[ei].type == KlTypePassword)
                    ? app->entries[ei].pwd.name
                    : app->entries[ei].key.name;
                bool sel = (start + r) == app->list_sel;
                if(sel) canvas_draw_box(canvas, 0, 14 + r * 14, 128, 13);
                canvas_set_color(canvas, sel ? ColorWhite : ColorBlack);
                canvas_draw_str(canvas, 4, 24 + r * 14, nm);
                canvas_set_color(canvas, ColorBlack);
            }
        }
        canvas_draw_str(canvas, 0, 62, "OK:detail  Back:menu");
        break;
    }
    case ScreenDetail: {
        uint8_t  idx[KL_MAX_ENTRIES];
        uint8_t  n = list_filtered(app, app->list_type, idx);
        if(app->list_sel < n) {
            KlEntry* e = &app->entries[idx[app->list_sel]];
            canvas_set_font(canvas, FontSecondary);
            if(e->type == KlTypePassword) {
                canvas_draw_str(canvas, 0, 10, e->pwd.name);
                // Mostrar password con wrap manual cada 21 chars
                char tmp[128 + 1];
                strncpy(tmp, e->pwd.password, 128);
                canvas_draw_str(canvas, 0, 24, tmp[0] ? tmp : "(empty)");
            } else {
                canvas_draw_str(canvas, 0, 10, e->key.name);
                const char* tstr = (e->key.type == KlTypeEd25519) ? "Ed25519" : "X25519";
                canvas_draw_str(canvas, 0, 22, tstr);
                // Mostrar primeros 16 bytes de pk en hex (32 hex chars)
                char hex[33];
                bytes_to_hex(e->key.pk, 16, hex, sizeof(hex));
                canvas_draw_str(canvas, 0, 34, "pk:");
                canvas_draw_str(canvas, 20, 34, hex);
            }
        }
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str(canvas, 0, 62, "Back:list");
        break;
    }
    case ScreenGenMenu: {
        canvas_set_font(canvas, FontPrimary);
        canvas_draw_str(canvas, 0, 10, "Generate");
        canvas_set_font(canvas, FontSecondary);
        for(uint8_t i = 0; i < 3; i++) {
            bool sel = (i == app->gmenu_sel);
            if(sel) canvas_draw_box(canvas, 0, 14 + i * 14, 128, 13);
            canvas_set_color(canvas, sel ? ColorWhite : ColorBlack);
            canvas_draw_str(canvas, 4, 24 + i * 14, GENMENU_LABELS[i]);
            canvas_set_color(canvas, ColorBlack);
        }
        break;
    }
    case ScreenResult: {
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str(canvas, 0, 10, app->result_label);
        // Wrap cada 21 chars aprox (128px / 6px por char)
        size_t len = strlen(app->result_buf);
        size_t cols = 21;
        for(uint8_t row = 0; row < 4 && row * cols < len; row++) {
            char tmp[22] = {0};
            strncpy(tmp, app->result_buf + row * cols, cols);
            canvas_draw_str(canvas, 0, 22 + row * 11, tmp);
        }
        canvas_draw_str(canvas, 0, 62, "Back:menu");
        break;
    }
    }

    furi_mutex_release(app->mutex);
}

static void input_cb(InputEvent* ev, void* ctx) {
    KlApp* app = ctx;
    KlEvent ke = { .type = EvtInput, .input = *ev };
    furi_message_queue_put(app->queue, &ke, 0);
}

// ─── Lógica de PIN ───────────────────────────────────────────────────────────
static void try_unlock(KlApp* app) {
    app->pin_str[0] = '0' + (app->pin_digits[0] % 10);
    app->pin_str[1] = '0' + (app->pin_digits[1] % 10);
    app->pin_str[2] = '0' + (app->pin_digits[2] % 10);
    app->pin_str[3] = '0' + (app->pin_digits[3] % 10);
    app->pin_str[4] = '\0';

    KlResult r = kl_store_load(app->pin_str, app->entries, &app->entry_count);
    if(r == KlOk) {
        app->menu_sel = 0;
        app->screen   = ScreenMenu;
        app->status[0] = '\0';
    } else if(r == KlErrNoFile) {
        // Primer uso: vault vacío, salvar vacío con este PIN
        app->entry_count = 0;
        kl_store_save(app->pin_str, app->entries, 0);
        app->menu_sel = 0;
        app->screen   = ScreenMenu;
        app->status[0] = '\0';
    } else if(r == KlErrBadPin) {
        strncpy(app->status, "Bad PIN!", sizeof(app->status));
        // Resetear cursor
        memset(app->pin_digits, 0, sizeof(app->pin_digits));
        app->pin_cursor = 0;
    } else {
        strncpy(app->status, "Vault error", sizeof(app->status));
        memset(app->pin_digits, 0, sizeof(app->pin_digits));
        app->pin_cursor = 0;
    }
}

// ─── Lógica de generación ────────────────────────────────────────────────────
static void do_generate(KlApp* app) {
    static uint8_t gen_counter = 0;
    gen_counter++;
    char name[KL_NAME_MAX + 1];

    if(app->gmenu_sel == 0) {
        // Ed25519
        uint8_t seed[32];
        snprintf(name, sizeof(name), "Ed25519_%u", gen_counter);
        KlResult r = kl_keygen_ed25519(app->entries, &app->entry_count, name, seed);
        if(r == KlOk) {
            kl_store_save(app->pin_str, app->entries, app->entry_count);
            char hex[65];
            bytes_to_hex(seed, 32, hex, sizeof(hex));
            crypto_wipe(seed, 32);
            snprintf(app->result_label, sizeof(app->result_label), "Ed25519 seed (backup!)");
            strncpy(app->result_buf, hex, sizeof(app->result_buf));
            app->screen = ScreenResult;
        } else {
            strncpy(app->result_label, "Error (vault full?)", sizeof(app->result_label));
            app->result_buf[0] = '\0';
            app->screen = ScreenResult;
        }
    } else if(app->gmenu_sel == 1) {
        // X25519
        uint8_t sk[32];
        snprintf(name, sizeof(name), "X25519_%u", gen_counter);
        KlResult r = kl_keygen_x25519(app->entries, &app->entry_count, name, sk);
        if(r == KlOk) {
            kl_store_save(app->pin_str, app->entries, app->entry_count);
            char hex[65];
            bytes_to_hex(sk, 32, hex, sizeof(hex));
            snprintf(app->result_label, sizeof(app->result_label), "X25519 sk (backup!)");
            strncpy(app->result_buf, hex, sizeof(app->result_buf));
            app->screen = ScreenResult;
        } else {
            strncpy(app->result_label, "Error (vault full?)", sizeof(app->result_label));
            app->result_buf[0] = '\0';
            app->screen = ScreenResult;
        }
    } else {
        // Password aleatorio 16 chars [A-Za-z0-9!@#$]
        static const char charset[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
        char pw[17] = {0};
        uint8_t rnd[16];
        furi_hal_random_fill_buf(rnd, 16);
        for(uint8_t i = 0; i < 16; i++) pw[i] = charset[rnd[i] % (sizeof(charset) - 1)];
        crypto_wipe(rnd, 16);

        if(app->entry_count < KL_MAX_ENTRIES) {
            snprintf(name, sizeof(name), "Pass_%u", gen_counter);
            KlEntry* e = &app->entries[app->entry_count++];
            memset(e, 0, sizeof(KlEntry));
            e->type = KlTypePassword;
            strncpy(e->pwd.name,     name, KL_NAME_MAX);
            strncpy(e->pwd.password, pw,   127);
            kl_store_save(app->pin_str, app->entries, app->entry_count);
        }
        snprintf(app->result_label, sizeof(app->result_label), "Generated password:");
        strncpy(app->result_buf, pw, sizeof(app->result_buf));
        memset(pw, 0, sizeof(pw));
        app->screen = ScreenResult;
    }
}

// ─── Entrada por pantalla ────────────────────────────────────────────────────
static void handle_input(KlApp* app, InputEvent* ev) {
    if(ev->type != InputTypeShort && ev->type != InputTypeRepeat) return;

    switch(app->screen) {
    case ScreenPin:
        if(ev->key == InputKeyUp) {
            app->pin_digits[app->pin_cursor] = (app->pin_digits[app->pin_cursor] + 1) % 10;
        } else if(ev->key == InputKeyDown) {
            app->pin_digits[app->pin_cursor] = (app->pin_digits[app->pin_cursor] + 9) % 10;
        } else if(ev->key == InputKeyOk || ev->key == InputKeyRight) {
            if(app->pin_cursor < PIN_LEN - 1) {
                app->pin_cursor++;
            } else {
                try_unlock(app);
            }
        } else if(ev->key == InputKeyBack && app->pin_cursor > 0) {
            app->pin_cursor--;
        }
        break;

    case ScreenMenu:
        if(ev->key == InputKeyUp)   app->menu_sel = (app->menu_sel + MENU_ITEMS - 1) % MENU_ITEMS;
        if(ev->key == InputKeyDown) app->menu_sel = (app->menu_sel + 1) % MENU_ITEMS;
        if(ev->key == InputKeyOk) {
            if(app->menu_sel == 0) {
                app->list_type = KlTypePassword;
                app->list_sel  = 0;
                app->screen    = ScreenList;
            } else if(app->menu_sel == 1) {
                app->list_type = KlTypeEd25519; // Keys muestra Ed25519+X25519
                app->list_sel  = 0;
                app->screen    = ScreenList;
            } else {
                app->gmenu_sel = 0;
                app->screen    = ScreenGenMenu;
            }
        }
        if(ev->key == InputKeyBack) {
            // Salir re-bloquea: limpiar vault
            crypto_wipe(app->entries, sizeof(app->entries));
            app->entry_count = 0;
            memset(app->pin_digits, 0, sizeof(app->pin_digits));
            memset(app->pin_str, 0, sizeof(app->pin_str));
            app->pin_cursor = 0;
            app->screen = ScreenPin;
        }
        break;

    case ScreenList: {
        uint8_t idx[KL_MAX_ENTRIES];
        uint8_t n;
        if(app->list_type == KlTypePassword) {
            n = list_filtered(app, KlTypePassword, idx);
        } else {
            uint8_t ib[KL_MAX_ENTRIES];
            uint8_t na = list_filtered(app, KlTypeEd25519, idx);
            uint8_t nb = list_filtered(app, KlTypeX25519,  ib);
            for(uint8_t j = 0; j < nb; j++) idx[na + j] = ib[j];
            n = na + nb;
        }
        if(ev->key == InputKeyUp   && app->list_sel > 0)       app->list_sel--;
        if(ev->key == InputKeyDown && app->list_sel + 1 < n)    app->list_sel++;
        if(ev->key == InputKeyOk)   app->screen = ScreenDetail;
        if(ev->key == InputKeyBack) { app->screen = ScreenMenu; app->list_sel = 0; }
        break;
    }

    case ScreenDetail:
        if(ev->key == InputKeyBack) app->screen = ScreenList;
        break;

    case ScreenGenMenu:
        if(ev->key == InputKeyUp)   app->gmenu_sel = (app->gmenu_sel + 2) % 3;
        if(ev->key == InputKeyDown) app->gmenu_sel = (app->gmenu_sel + 1) % 3;
        if(ev->key == InputKeyOk)   do_generate(app);
        if(ev->key == InputKeyBack) app->screen = ScreenMenu;
        break;

    case ScreenResult:
        if(ev->key == InputKeyBack || ev->key == InputKeyOk) app->screen = ScreenMenu;
        break;
    }
}

// ─── Entry point ─────────────────────────────────────────────────────────────
int32_t key_locker_app(void* p) {
    (void)p;
    KlApp* app = malloc(sizeof(KlApp));
    memset(app, 0, sizeof(KlApp));
    app->screen = ScreenPin;

    app->mutex = furi_mutex_alloc(FuriMutexTypeNormal);
    app->queue = furi_message_queue_alloc(8, sizeof(KlEvent));
    app->vp    = view_port_alloc();
    view_port_draw_callback_set(app->vp, draw_cb, app);
    view_port_input_callback_set(app->vp, input_cb, app);
    app->gui = furi_record_open(RECORD_GUI);
    gui_add_view_port(app->gui, app->vp, GuiLayerFullscreen);

    KlEvent ev;
    while(furi_message_queue_get(app->queue, &ev, FuriWaitForever) == FuriStatusOk) {
        if(ev.type == EvtInput) {
            if(ev.input.type == InputTypeShort && ev.input.key == InputKeyBack &&
               app->screen == ScreenPin) {
                break; // salir del app
            }
            furi_mutex_acquire(app->mutex, FuriWaitForever);
            handle_input(app, &ev.input);
            furi_mutex_release(app->mutex);
            view_port_update(app->vp);
        }
    }

    // Cleanup: wipe todo lo sensible
    furi_mutex_acquire(app->mutex, FuriWaitForever);
    crypto_wipe(app->entries, sizeof(app->entries));
    crypto_wipe(app->pin_str, sizeof(app->pin_str));
    memset(app->pin_digits, 0, sizeof(app->pin_digits));
    crypto_wipe(app->result_buf, sizeof(app->result_buf));
    furi_mutex_release(app->mutex);

    gui_remove_view_port(app->gui, app->vp);
    furi_record_close(RECORD_GUI);
    view_port_free(app->vp);
    furi_message_queue_free(app->queue);
    furi_mutex_free(app->mutex);
    free(app);
    return 0;
}
