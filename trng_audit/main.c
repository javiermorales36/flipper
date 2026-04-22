#include <furi.h>
#include <furi_hal_random.h>
#include <gui/gui.h>
#include <gui/modules/submenu.h>
#include <gui/modules/text_box.h>
#include <gui/view_dispatcher.h>
#include <storage/storage.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TRNG_AUDIT_QUICK_BITS 2048u
#define TRNG_AUDIT_DEEP_BITS 8192u
#define TRNG_AUDIT_MAX_BITS TRNG_AUDIT_DEEP_BITS
#define TRNG_AUDIT_MAX_BYTES (TRNG_AUDIT_MAX_BITS / 8u)
#define TRNG_AUDIT_REPORT_PATH "/ext/trng_audit_report.txt"

typedef enum {
    TrngAuditViewMenu,
    TrngAuditViewTextBox,
} TrngAuditView;

typedef enum {
    TrngAuditActionQuick,
    TrngAuditActionDeep,
    TrngAuditActionSave,
    TrngAuditActionAbout,
} TrngAuditAction;

typedef struct {
    ViewDispatcher* view_dispatcher;
    Submenu* submenu;
    TextBox* text_box;
    TrngAuditView current_view;
    bool has_report;
    char report[1600];
    char status[1600];
} TrngAuditApp;

static void trng_audit_refresh_menu(TrngAuditApp* app);
static void trng_audit_show_text(TrngAuditApp* app, const char* text);
static void trng_audit_menu_callback(void* context, uint32_t index);
static bool trng_audit_navigation_callback(void* context);

static bool trng_audit_write_text_file(const char* path, const char* text) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* file = storage_file_alloc(storage);
    const size_t text_length = strlen(text);
    bool ok = false;

    if(storage_file_open(file, path, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        ok = storage_file_write(file, text, text_length) == text_length;
        if(ok) {
            ok = storage_file_sync(file);
        }
    }

    storage_file_close(file);
    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
    return ok;
}

static uint8_t trng_audit_popcount8(uint8_t value) {
    uint8_t count = 0u;
    while(value != 0u) {
        count += (uint8_t)(value & 1u);
        value >>= 1u;
    }
    return count;
}

static uint8_t trng_audit_get_bit(const uint8_t* buffer, uint32_t bit_index) {
    const uint32_t byte_index = bit_index / 8u;
    const uint32_t bit_offset = 7u - (bit_index % 8u);
    return (uint8_t)((buffer[byte_index] >> bit_offset) & 1u);
}

static uint32_t trng_audit_isqrt(uint32_t value) {
    uint32_t result = 0u;
    uint32_t bit = 1u << 30;

    while(bit > value) {
        bit >>= 2u;
    }

    while(bit != 0u) {
        if(value >= result + bit) {
            value -= result + bit;
            result = (result >> 1u) + bit;
        } else {
            result >>= 1u;
        }
        bit >>= 2u;
    }

    return result;
}

static void trng_audit_run_sample(TrngAuditApp* app, uint32_t bit_count) {
    uint8_t sample[TRNG_AUDIT_MAX_BYTES];
    uint32_t nibble_histogram[16];
    uint32_t ones = 0u;
    uint32_t runs = 0u;
    uint32_t mismatches = 0u;
    uint64_t sum_sq = 0u;
    uint32_t previous_bit = 0u;

    memset(sample, 0, sizeof(sample));
    memset(nibble_histogram, 0, sizeof(nibble_histogram));

    furi_hal_random_fill_buf(sample, bit_count / 8u);

    for(uint32_t byte_index = 0u; byte_index < (bit_count / 8u); byte_index++) {
        ones += trng_audit_popcount8(sample[byte_index]);
        nibble_histogram[(sample[byte_index] >> 4u) & 0x0Fu]++;
        nibble_histogram[sample[byte_index] & 0x0Fu]++;
    }

    previous_bit = trng_audit_get_bit(sample, 0u);
    runs = 1u;
    for(uint32_t bit_index = 1u; bit_index < bit_count; bit_index++) {
        const uint32_t current_bit = trng_audit_get_bit(sample, bit_index);
        if(current_bit != previous_bit) {
            runs++;
        }
        previous_bit = current_bit;
        mismatches += current_bit != trng_audit_get_bit(sample, bit_index - 1u);
    }

    for(size_t histogram_index = 0u; histogram_index < 16u; histogram_index++) {
        sum_sq += (uint64_t)nibble_histogram[histogram_index] * (uint64_t)nibble_histogram[histogram_index];
    }

    const uint32_t zeros = bit_count - ones;
    const uint32_t ones_permille = (ones * 1000u) / bit_count;
    const uint32_t mismatch_permille = (mismatches * 1000u) / (bit_count - 1u);
    const uint32_t expected_runs = 1u + (uint32_t)(((uint64_t)2u * ones * zeros) / bit_count);
    const uint32_t runs_delta = (runs > expected_runs) ? (runs - expected_runs) : (expected_runs - runs);
    const uint32_t runs_band = 3u * trng_audit_isqrt(bit_count);
    const uint32_t poker_blocks = bit_count / 4u;
    const uint32_t poker_score_milli = (uint32_t)(((16u * sum_sq * 1000u) / poker_blocks) - (poker_blocks * 1000u));

    const bool monobit_ok = ones_permille >= 470u && ones_permille <= 530u;
    const bool runs_ok = runs_delta <= runs_band;
    const bool poker_ok = poker_score_milli >= 4000u && poker_score_milli <= 40000u;
    const bool autocorr_ok = mismatch_permille >= 470u && mismatch_permille <= 530u;
    const bool overall_ok = monobit_ok && runs_ok && poker_ok && autocorr_ok;

    snprintf(
        app->report,
        sizeof(app->report),
        "Auditor TRNG\n\nBits: %u\nMonobit: %u permil (%s)\nRachas: %u esp %u delta %u banda %u (%s)\nPoker4: %u mili (%s)\nAutocorr lag1: %u permil (%s)\n\nGeneral: %s\n\nHeuristicas rapidas de salud del TRNG hardware. No es una validacion SP 800-22 completa.",
        (unsigned int)bit_count,
        (unsigned int)ones_permille,
        monobit_ok ? "OK" : "FUERA",
        (unsigned int)runs,
        (unsigned int)expected_runs,
        (unsigned int)runs_delta,
        (unsigned int)runs_band,
        runs_ok ? "OK" : "FUERA",
        (unsigned int)poker_score_milli,
        poker_ok ? "OK" : "FUERA",
        (unsigned int)mismatch_permille,
        autocorr_ok ? "OK" : "FUERA",
        overall_ok ? "SANO" : "SOSPECHOSO");

    app->has_report = true;
    trng_audit_show_text(app, app->report);
}

static void trng_audit_show_text(TrngAuditApp* app, const char* text) {
    text_box_reset(app->text_box);
    text_box_set_text(app->text_box, text);
    app->current_view = TrngAuditViewTextBox;
    view_dispatcher_switch_to_view(app->view_dispatcher, TrngAuditViewTextBox);
}

static void trng_audit_refresh_menu(TrngAuditApp* app) {
    submenu_reset(app->submenu);
    submenu_set_header(app->submenu, "Auditor TRNG\nComprobaciones de entropia");
    submenu_add_item(app->submenu, "Analisis rapido 2048b", TrngAuditActionQuick, trng_audit_menu_callback, app);
    submenu_add_item(app->submenu, "Analisis profundo 8192b", TrngAuditActionDeep, trng_audit_menu_callback, app);
    submenu_add_item(app->submenu, "Guardar ultimo informe", TrngAuditActionSave, trng_audit_menu_callback, app);
    submenu_add_item(app->submenu, "Acerca de", TrngAuditActionAbout, trng_audit_menu_callback, app);
}

static void trng_audit_menu_callback(void* context, uint32_t index) {
    TrngAuditApp* app = context;

    switch(index) {
    case TrngAuditActionQuick:
        trng_audit_run_sample(app, TRNG_AUDIT_QUICK_BITS);
        break;
    case TrngAuditActionDeep:
        trng_audit_run_sample(app, TRNG_AUDIT_DEEP_BITS);
        break;
    case TrngAuditActionSave:
        if(!app->has_report) {
            snprintf(app->status, sizeof(app->status), "Ejecuta una muestra primero.");
        } else if(trng_audit_write_text_file(TRNG_AUDIT_REPORT_PATH, app->report)) {
            snprintf(app->status, sizeof(app->status), "Informe guardado en:\n%s", TRNG_AUDIT_REPORT_PATH);
        } else {
            snprintf(app->status, sizeof(app->status), "Error al escribir:\n%s", TRNG_AUDIT_REPORT_PATH);
        }
        trng_audit_show_text(app, app->status);
        break;
    case TrngAuditActionAbout:
        app->has_report = false;
        snprintf(
            app->status,
            sizeof(app->status),
            "Auditor TRNG\n\nRealiza comprobaciones rapidas sobre muestras del RNG hardware del Flipper. Informa sobre el balance de monobit, estabilidad de rachas, dispersion poker de 4 bits y autocorrelacion lag-1.\n\nUsalo como pantalla de salud del dispositivo, no como certificado de validacion formal.");
        trng_audit_show_text(app, app->status);
        break;
    }
}

static bool trng_audit_navigation_callback(void* context) {
    TrngAuditApp* app = context;

    if(app->current_view != TrngAuditViewMenu) {
        app->current_view = TrngAuditViewMenu;
        view_dispatcher_switch_to_view(app->view_dispatcher, TrngAuditViewMenu);
        return true;
    }

    return false;
}

static TrngAuditApp* trng_audit_app_alloc(void) {
    TrngAuditApp* app = malloc(sizeof(TrngAuditApp));
    furi_assert(app);

    memset(app, 0, sizeof(TrngAuditApp));
    app->view_dispatcher = view_dispatcher_alloc();
    app->submenu = submenu_alloc();
    app->text_box = text_box_alloc();

    view_dispatcher_set_event_callback_context(app->view_dispatcher, app);
    view_dispatcher_set_navigation_event_callback(app->view_dispatcher, trng_audit_navigation_callback);

    view_dispatcher_add_view(app->view_dispatcher, TrngAuditViewMenu, submenu_get_view(app->submenu));
    view_dispatcher_add_view(app->view_dispatcher, TrngAuditViewTextBox, text_box_get_view(app->text_box));

    trng_audit_refresh_menu(app);
    return app;
}

static void trng_audit_app_free(TrngAuditApp* app) {
    furi_assert(app);

    view_dispatcher_remove_view(app->view_dispatcher, TrngAuditViewMenu);
    view_dispatcher_remove_view(app->view_dispatcher, TrngAuditViewTextBox);

    text_box_free(app->text_box);
    submenu_free(app->submenu);
    view_dispatcher_free(app->view_dispatcher);
    free(app);
}

int32_t trng_audit_app(void* p) {
    UNUSED(p);

    TrngAuditApp* app = trng_audit_app_alloc();
    Gui* gui = furi_record_open(RECORD_GUI);

    view_dispatcher_attach_to_gui(app->view_dispatcher, gui, ViewDispatcherTypeFullscreen);
    app->current_view = TrngAuditViewMenu;
    view_dispatcher_switch_to_view(app->view_dispatcher, TrngAuditViewMenu);
    view_dispatcher_run(app->view_dispatcher);

    trng_audit_app_free(app);
    furi_record_close(RECORD_GUI);
    return 0;
}