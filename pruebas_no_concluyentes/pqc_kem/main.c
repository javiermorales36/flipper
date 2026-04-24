#include <furi.h>
#include <gui/gui.h>
#include <gui/elements.h>
#include <input/input.h>
#include <furi_hal.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "lib/kyber512/kem.h"
#include "lib/kyber512/params.h"

// ─── Estado ───────────────────────────────────────────────────────────────────
typedef enum {
    StateIdle = 0,   // pantalla inicial
    StateRunning,    // ejecutando KEM (bloqueante breve)
    StateOk,         // resultado OK
    StateErr,        // error
} PqcState;

typedef struct {
    PqcState      state;
    bool          ss_match;
    char          ss_alice_hex[17]; // primeros 8B de ss_alice
    char          ss_bob_hex[17];   // primeros 8B de ss_bob
    uint32_t      elapsed_ms;
    char          status[48];

    FuriMutex*        mutex;
    FuriMessageQueue* queue;
    ViewPort*         vp;
    Gui*              gui;
} PqcApp;

typedef struct { InputEvent input; } PqcEvent;

// ─── Render ───────────────────────────────────────────────────────────────────
static void draw_cb(Canvas* canvas, void* ctx) {
    PqcApp* app = ctx;
    furi_mutex_acquire(app->mutex, FuriWaitForever);
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 0, 10, "ML-KEM-512 Demo");

    canvas_set_font(canvas, FontSecondary);
    switch(app->state) {
    case StateIdle:
        canvas_draw_str(canvas, 0, 26, "Kyber-512 / ML-KEM-512");
        canvas_draw_str(canvas, 0, 36, "pk=800B sk=1632B ct=768B");
        canvas_draw_str(canvas, 0, 46, "ss=32B  (NIST Level 1)");
        canvas_draw_str(canvas, 0, 62, "OK: run  Back: exit");
        break;
    case StateRunning:
        canvas_draw_str(canvas, 0, 36, "Running KEM...");
        break;
    case StateOk: {
        char line[48];
        canvas_draw_str(canvas, 0, 22, app->ss_match ? "SharedSecret: MATCH" : "SharedSecret: FAIL!");
        snprintf(line, sizeof(line), "Alice: %s", app->ss_alice_hex);
        canvas_draw_str(canvas, 0, 32, line);
        snprintf(line, sizeof(line), "Bob:   %s", app->ss_bob_hex);
        canvas_draw_str(canvas, 0, 42, line);
        snprintf(line, sizeof(line), "%lu ms", (unsigned long)app->elapsed_ms);
        canvas_draw_str(canvas, 0, 52, line);
        canvas_draw_str(canvas, 0, 62, "OK: again  Back: exit");
        break;
    }
    case StateErr:
        canvas_draw_str(canvas, 0, 30, app->status);
        canvas_draw_str(canvas, 0, 62, "Back: exit");
        break;
    }
    furi_mutex_release(app->mutex);
}

static void input_cb(InputEvent* ev, void* ctx) {
    PqcApp* app = ctx;
    PqcEvent pe = { .input = *ev };
    furi_message_queue_put(app->queue, &pe, 0);
}

// ─── Operación KEM (en el contexto del loop, sin thread extra) ────────────────
static void run_kem(PqcApp* app) {
    // Todos los buffers grandes en HEAP — stack_size solo 4KB
    uint8_t* pk     = malloc(KYBER_PUBLICKEYBYTES);
    uint8_t* sk     = malloc(KYBER_SECRETKEYBYTES);
    uint8_t* ct     = malloc(KYBER_CIPHERTEXTBYTES);
    uint8_t* ss_enc = malloc(KYBER_SSBYTES);  // shared secret del encapsulador
    uint8_t* ss_dec = malloc(KYBER_SSBYTES);  // shared secret del desencapsulador

    if(!pk || !sk || !ct || !ss_enc || !ss_dec) {
        strncpy(app->status, "malloc failed", sizeof(app->status));
        app->state = StateErr;
        goto cleanup;
    }

    uint32_t t0 = furi_get_tick();

    // 1. Keypair (Alice)
    if(crypto_kem_keypair(pk, sk) != 0) {
        strncpy(app->status, "keypair failed", sizeof(app->status));
        app->state = StateErr;
        goto cleanup;
    }

    // 2. Encapsulate (Bob → Alice): ct + ss_enc
    if(crypto_kem_enc(ct, ss_enc, pk) != 0) {
        strncpy(app->status, "enc failed", sizeof(app->status));
        app->state = StateErr;
        goto cleanup;
    }

    // 3. Decapsulate (Alice): ss_dec
    if(crypto_kem_dec(ss_dec, ct, sk) != 0) {
        strncpy(app->status, "dec failed", sizeof(app->status));
        app->state = StateErr;
        goto cleanup;
    }

    uint32_t t1  = furi_get_tick();
    app->elapsed_ms = (t1 - t0) * 1000 / furi_kernel_get_tick_frequency();

    // Comparar (memcmp — timing no importa aquí, es demo)
    app->ss_match = (memcmp(ss_enc, ss_dec, KYBER_SSBYTES) == 0);

    // Mostrar primeros 8 bytes en hex
    for(int i = 0; i < 8; i++) {
        snprintf(app->ss_alice_hex + i * 2, 3, "%02x", ss_enc[i]);
        snprintf(app->ss_bob_hex   + i * 2, 3, "%02x", ss_dec[i]);
    }
    app->ss_alice_hex[16] = '\0';
    app->ss_bob_hex[16]   = '\0';

    // Wipe secretos
    memset(ss_enc, 0, KYBER_SSBYTES);
    memset(ss_dec, 0, KYBER_SSBYTES);
    memset(sk,     0, KYBER_SECRETKEYBYTES);

    app->state = StateOk;

cleanup:
    if(pk)     free(pk);
    if(sk)     free(sk);
    if(ct)     free(ct);
    if(ss_enc) free(ss_enc);
    if(ss_dec) free(ss_dec);
}

// ─── Entry point ─────────────────────────────────────────────────────────────
int32_t pqc_kem_app(void* p) {
    (void)p;
    PqcApp* app = malloc(sizeof(PqcApp));
    memset(app, 0, sizeof(PqcApp));
    app->state = StateIdle;

    app->mutex = furi_mutex_alloc(FuriMutexTypeNormal);
    app->queue = furi_message_queue_alloc(4, sizeof(PqcEvent));
    app->vp    = view_port_alloc();
    view_port_draw_callback_set(app->vp, draw_cb, app);
    view_port_input_callback_set(app->vp, input_cb, app);
    app->gui = furi_record_open(RECORD_GUI);
    gui_add_view_port(app->gui, app->vp, GuiLayerFullscreen);

    PqcEvent ev;
    bool running = true;
    while(running && furi_message_queue_get(app->queue, &ev, FuriWaitForever) == FuriStatusOk) {
        if(ev.input.type != InputTypeShort) continue;
        if(ev.input.key == InputKeyBack) {
            running = false;
            break;
        }
        if(ev.input.key == InputKeyOk) {
            furi_mutex_acquire(app->mutex, FuriWaitForever);
            app->state = StateRunning;
            furi_mutex_release(app->mutex);
            view_port_update(app->vp);

            // Correr KEM (bloquea el hilo de la app ~100-500ms en Cortex-M4)
            furi_mutex_acquire(app->mutex, FuriWaitForever);
            run_kem(app);
            furi_mutex_release(app->mutex);
            view_port_update(app->vp);
        }
    }

    gui_remove_view_port(app->gui, app->vp);
    furi_record_close(RECORD_GUI);
    view_port_free(app->vp);
    furi_message_queue_free(app->queue);
    furi_mutex_free(app->mutex);
    free(app);
    return 0;
}
