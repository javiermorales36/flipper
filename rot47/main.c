#include <furi.h>
#include <gui/gui.h>
#include <gui/modules/submenu.h>
#include <gui/modules/text_box.h>
#include <gui/modules/text_input.h>
#include <gui/modules/widget.h>
#include <gui/scene_manager.h>
#include <gui/view_dispatcher.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Different app scenes
typedef enum {
  MainMenuScene,
  Rot47InputScene,
  Rot47CipherMessageScene,
  ReadmeScene,
  Rot47SceneCount,
} Rot47Scene;

// View references
typedef enum {
  Rot47SubmenuView,
  Rot47WidgetView,
  Rot47TextInputView,
  Rot47TextBoxView,
} Rot47View;

// App object
typedef struct App {
  SceneManager *scene_manager;
  ViewDispatcher *view_dispatcher;
  Submenu *submenu;
  Widget *widget;
  TextInput *text_input;
  TextBox *text_box;
  char *rot47_text;
  uint8_t rot47_text_size;
} App;

// Reference to item menus. Avoid magic numbers
typedef enum {
  MainMenuSceneCipherToRot47,
  MainMenuSceneReadme,
} MainMenuSceneIndex;

// Reference to custom events. Avoid magic numbers
typedef enum {
  MainMenuSceneCipherToRot47Event,
  MainMenuSceneReadmeEvent,
} Rot47MainMenuEvent;

typedef enum {
  Rot47CipherInputSceneSaveEvent,
} Rot47CipherInputEvent;

// ROT47 Function in C
char *rot47(const char *src) {
  if (src == NULL) {
    return NULL;
  }

  char *result = malloc(strlen(src) + 1);

  if (result != NULL) {
    strcpy(result, src);
    char *current_char = result;

    while (*current_char != '\0') {
      if (*current_char >= 33 && *current_char <= 126) {
        *current_char = 33 + ((*current_char - 33 + 47) % 94);
      }
      current_char++;
    }
  }
  return result;
}

// Function for stub menu
void rot47_menu_callback(void *context, uint32_t index) {
  App *app = context;
  switch (index) {
  case MainMenuSceneReadme:
    scene_manager_handle_custom_event(app->scene_manager,
                                      MainMenuSceneReadmeEvent);
    break;
  case MainMenuSceneCipherToRot47:
    scene_manager_handle_custom_event(app->scene_manager,
                                      MainMenuSceneCipherToRot47Event);
    break;
  }
}

// Functions for every scene
void rot47_main_menu_scene_on_enter(void *context) {
  App *app = context;
  submenu_reset(app->submenu);
  submenu_set_header(app->submenu, "ROT47 Cipher");
  submenu_add_item(app->submenu, "Cipher with ROT47",
                   MainMenuSceneCipherToRot47, rot47_menu_callback, app);
  submenu_add_item(app->submenu, "Readme", MainMenuSceneReadme,
                   rot47_menu_callback, app);
  view_dispatcher_switch_to_view(app->view_dispatcher, Rot47SubmenuView);
}

bool rot47_main_menu_scene_on_event(void *context, SceneManagerEvent event) {
  App *app = context;
  bool consumed = false;
  switch (event.type) {
  case SceneManagerEventTypeCustom:
    switch (event.event) {
    case MainMenuSceneReadmeEvent:
      scene_manager_next_scene(app->scene_manager, ReadmeScene);
      consumed = true;
      break;
    case MainMenuSceneCipherToRot47Event:
      scene_manager_next_scene(app->scene_manager, Rot47InputScene);
      consumed = true;
      break;
    }
    break;
  default:
    break;
  }
  return consumed;
}

void main_menu_scene_on_exit(void *context) {
  App *app = context;
  submenu_reset(app->submenu);
}

void text_input_callback(void *context) {
  App *app = context;
  scene_manager_handle_custom_event(app->scene_manager,
                                    Rot47CipherInputSceneSaveEvent);
}

void rot47_input_scene_on_enter(void *context) {
  App *app = context;
  bool clear_text = true;
  text_input_reset(app->text_input);
  text_input_set_header_text(app->text_input, "Enter text to cipher");
  text_input_set_result_callback(app->text_input, text_input_callback, app,
                                 app->rot47_text, app->rot47_text_size,
                                 clear_text);
  view_dispatcher_switch_to_view(app->view_dispatcher, Rot47TextInputView);
}

bool rot47_greeting_input_scene_on_event(void *context,
                                         SceneManagerEvent event) {
  App *app = context;
  bool consumed = false;
  if (event.type == SceneManagerEventTypeCustom) {
    if (event.event == Rot47CipherInputSceneSaveEvent) {
      scene_manager_next_scene(app->scene_manager, Rot47CipherMessageScene);
      consumed = true;
    }
  }
  return consumed;
}

void rot47_greeting_input_scene_on_exit(void *context) { UNUSED(context); }

void transform_rot47_on_enter(void *context) {
  App *app = context;
  text_box_reset(app->text_box);
  text_box_set_text(app->text_box, rot47(app->rot47_text));
  view_dispatcher_switch_to_view(app->view_dispatcher, Rot47TextBoxView);
}

bool rot47_greeting_message_scene_on_event(void *context,
                                           SceneManagerEvent event) {
  UNUSED(context);
  UNUSED(event);
  return false; // event not handled.
}

void rot47_greeting_message_scene_on_exit(void *context) {
  App *app = context;
  widget_reset(app->widget);
}

void readme_scene_on_enter(void *context) {
  App *app = context;
  text_box_reset(app->text_box);
  text_box_set_text(
      app->text_box,
      "ROT47 is a simple letter substitution cipher that replaces a letter "
      "with the 47th "
      "letter after it in the ASCII table.\n"
      "For example:\n"
      "HELLO = w6==@ = HELLO\n"
      "So ROT47 works for \"cipher\" and \"decipher\" at the same time.\n"
      "Source: Wikipedia\nThis application was developed by "
      "Javier Morales.\nSee the repo on github:\n"
      "https://github.com/javiermorales36");
  view_dispatcher_switch_to_view(app->view_dispatcher, Rot47TextBoxView);
}

bool readme_scene_on_event(void *context, SceneManagerEvent event) {
  UNUSED(context);
  UNUSED(event);
  return false; // event not handled.
}

void readme_scene_on_exit(void *context) {
  App *app = context;
  submenu_reset(app->submenu);
}

// Arrays for the handlers
void (*const rot47_scene_on_enter_handlers[])(void *) = {
    rot47_main_menu_scene_on_enter,
    rot47_input_scene_on_enter,
    transform_rot47_on_enter,
    readme_scene_on_enter,
};

bool (*const rot47_scene_on_event_handlers[])(void *, SceneManagerEvent) = {
    rot47_main_menu_scene_on_event,
    rot47_greeting_input_scene_on_event,
    rot47_greeting_message_scene_on_event,
    readme_scene_on_event,
};

void (*const rot47_scene_on_exit_handlers[])(void *) = {
    main_menu_scene_on_exit,
    rot47_greeting_input_scene_on_exit,
    rot47_greeting_message_scene_on_exit,
    readme_scene_on_exit,
};

static const SceneManagerHandlers rot47_scene_manager_handlers = {
    .on_enter_handlers = rot47_scene_on_enter_handlers,
    .on_event_handlers = rot47_scene_on_event_handlers,
    .on_exit_handlers = rot47_scene_on_exit_handlers,
    .scene_num = Rot47SceneCount,
};

// This function is called when a custom event happens
// This event can be triggered when some pin is connected, a timer, etc
static bool basic_scene_custom_callback(void *context, uint32_t custom_event) {
  furi_assert(context);
  App *app = context;
  return scene_manager_handle_custom_event(app->scene_manager, custom_event);
}

// This is the function for the back button
bool basic_scene_back_event_callback(void *context) {
  furi_assert(context);
  App *app = context;
  return scene_manager_handle_back_event(app->scene_manager);
}

// Alloc for our app
// This is for allocate the memory of our app
static App *app_alloc() {
  App *app = malloc(sizeof(App));
  app->rot47_text_size = 128;
  app->rot47_text = malloc(app->rot47_text_size);
  app->scene_manager = scene_manager_alloc(&rot47_scene_manager_handlers, app);
  app->view_dispatcher = view_dispatcher_alloc();
  view_dispatcher_set_event_callback_context(app->view_dispatcher, app);
  view_dispatcher_set_custom_event_callback(app->view_dispatcher,
                                            basic_scene_custom_callback);
  view_dispatcher_set_navigation_event_callback(
      app->view_dispatcher, basic_scene_back_event_callback);
  app->submenu = submenu_alloc();
  view_dispatcher_add_view(app->view_dispatcher, Rot47SubmenuView,
                           submenu_get_view(app->submenu));
  app->widget = widget_alloc();
  view_dispatcher_add_view(app->view_dispatcher, Rot47WidgetView,
                           widget_get_view(app->widget));
  app->text_input = text_input_alloc();
  view_dispatcher_add_view(app->view_dispatcher, Rot47TextInputView,
                           text_input_get_view(app->text_input));
  app->text_box = text_box_alloc();
  view_dispatcher_add_view(app->view_dispatcher, Rot47TextBoxView,
                           text_box_get_view(app->text_box));
  return app;
}

// For free the memory of the app
static void app_free(App *app) {
  furi_assert(app);
  view_dispatcher_remove_view(app->view_dispatcher, Rot47SubmenuView);
  view_dispatcher_remove_view(app->view_dispatcher, Rot47WidgetView);
  view_dispatcher_remove_view(app->view_dispatcher, Rot47TextInputView);
  view_dispatcher_remove_view(app->view_dispatcher, Rot47TextBoxView);
  scene_manager_free(app->scene_manager);
  view_dispatcher_free(app->view_dispatcher);
  submenu_free(app->submenu);
  widget_free(app->widget);
  text_input_free(app->text_input);
  text_box_free(app->text_box);
  free(app);
}

int32_t rot47_main(void *p) {
  UNUSED(p);
  App *app = app_alloc();

  Gui *gui = furi_record_open(RECORD_GUI);
  view_dispatcher_attach_to_gui(app->view_dispatcher, gui,
                                ViewDispatcherTypeFullscreen);
  scene_manager_next_scene(app->scene_manager, MainMenuScene);
  view_dispatcher_run(app->view_dispatcher);

  app_free(app);
  return 0;
}