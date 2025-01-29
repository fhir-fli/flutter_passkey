#ifndef FLUTTER_PLUGIN_FLUTTER_PASSKEY_PLUGIN_H_
#define FLUTTER_PLUGIN_FLUTTER_PASSKEY_PLUGIN_H_

#include <flutter_linux/flutter_linux.h>
#include <gtk/gtk.h>

G_BEGIN_DECLS

#define FLUTTER_PASSKEY_PLUGIN(obj) \
  (G_TYPE_CHECK_INSTANCE_CAST((obj), flutter_passkey_plugin_get_type(), \
                              FlutterPasskeyPlugin))

typedef struct _FlutterPasskeyPlugin FlutterPasskeyPlugin;
typedef struct {
  GObjectClass parent_class;
} FlutterPasskeyPluginClass;

GType flutter_passkey_plugin_get_type();

void flutter_passkey_plugin_register_with_registrar(
    FlPluginRegistrar* registrar);

G_END_DECLS

#endif  // FLUTTER_PLUGIN_FLUTTER_PASSKEY_PLUGIN_H_
