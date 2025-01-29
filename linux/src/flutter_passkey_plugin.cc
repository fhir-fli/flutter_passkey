#include "flutter_passkey_plugin.h"

#include <flutter_linux/flutter_linux.h>
#include <gtk/gtk.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/ecdsa.h>
#include <cstring>
#include <vector>
#include <string>
#include <glib.h> // for g_base64_encode

#define FLUTTER_PASSKEY_PLUGIN(obj) \
  (G_TYPE_CHECK_INSTANCE_CAST((obj), flutter_passkey_plugin_get_type(), FlutterPasskeyPlugin))

struct _FlutterPasskeyPlugin {
  GObject parent_instance;
};

G_DEFINE_TYPE(FlutterPasskeyPlugin, flutter_passkey_plugin, g_object_get_type())

static const char* PRIVATE_KEY_FILE = "/home/user/.passkey_private.pem";

// Generate an EC key, save the private key to file, return public key in PEM format.
static std::string generate_passkey() {
  EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  if (!ec_key || !EC_KEY_generate_key(ec_key)) {
    if (ec_key) EC_KEY_free(ec_key);
    return "Error: Failed to generate key";
  }

  FILE* priv_file = fopen(PRIVATE_KEY_FILE, "w");
  if (!priv_file) {
    EC_KEY_free(ec_key);
    return "Error: Unable to save private key";
  }
  PEM_write_ECPrivateKey(priv_file, ec_key, nullptr, nullptr, 0, nullptr, nullptr);
  fclose(priv_file);

  // Convert public key to PEM
  BIO* pub_mem = BIO_new(BIO_s_mem());
  PEM_write_bio_EC_PUBKEY(pub_mem, ec_key);

  char* pub_data = nullptr;
  long pub_len = BIO_get_mem_data(pub_mem, &pub_data);
  std::string pub_key(pub_data, pub_len);

  BIO_free(pub_mem);
  EC_KEY_free(ec_key);

  return pub_key;
}

// Sign a challenge string using the stored private key. Return base64-encoded DER signature.
static std::string sign_challenge(const std::string& challenge) {
  // Load private key
  FILE* priv_file = fopen(PRIVATE_KEY_FILE, "r");
  if (!priv_file) {
    return "Error: No stored passkey found";
  }
  EC_KEY* ec_key = PEM_read_ECPrivateKey(priv_file, nullptr, nullptr, nullptr);
  fclose(priv_file);

  if (!ec_key) {
    return "Error: Unable to load private key";
  }

  // Hash
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256(reinterpret_cast<const unsigned char*>(challenge.data()), challenge.size(), hash);

  ECDSA_SIG* signature = ECDSA_do_sign(hash, SHA256_DIGEST_LENGTH, ec_key);
  if (!signature) {
    EC_KEY_free(ec_key);
    return "Error: Signing failed";
  }

  // DER encode
  int der_len = i2d_ECDSA_SIG(signature, nullptr);
  if (der_len <= 0) {
    ECDSA_SIG_free(signature);
    EC_KEY_free(ec_key);
    return "Error: DER encoding failed";
  }

  std::vector<unsigned char> der(der_len);
  unsigned char* der_ptr = der.data();
  i2d_ECDSA_SIG(signature, &der_ptr);

  ECDSA_SIG_free(signature);
  EC_KEY_free(ec_key);

  // Base64
  gchar* base64_data = g_base64_encode(der.data(), der.size());
  std::string base64_sig(base64_data);
  g_free(base64_data);

  return base64_sig;
}

// Modern method-call handler
static void handle_method_call(
    FlMethodChannel* channel,
    FlMethodCall* method_call,
    gpointer user_data) {
  FlutterPasskeyPlugin* self = FLUTTER_PASSKEY_PLUGIN(user_data);

  const gchar* method = fl_method_call_get_name(method_call);
  FlValue* args = fl_method_call_get_args(method_call);

  // Default = not implemented
  g_autoptr(FlMethodResponse) response =
      FL_METHOD_RESPONSE(fl_method_not_implemented_response_new());

  if (strcmp(method, "getPlatformVersion") == 0) {
    g_autoptr(FlValue) result = fl_value_new_string("Linux Passkey Support v1.0");
    response = FL_METHOD_RESPONSE(fl_method_success_response_new(result));

  } else if (strcmp(method, "createCredential") == 0) {
    // parse map { "options": ??? }
    if (args && fl_value_get_type(args) == FL_VALUE_TYPE_MAP) {
      FlValue* options_val = fl_value_lookup_string(args, "options");
      if (options_val && fl_value_get_type(options_val) == FL_VALUE_TYPE_STRING) {
        const gchar* someString = fl_value_get_string(options_val);
        // we can ignore or log it, up to you
      }
    }
    std::string pub_key = generate_passkey();
    g_autoptr(FlValue) result = fl_value_new_string(pub_key.c_str());
    response = FL_METHOD_RESPONSE(fl_method_success_response_new(result));

  } else if (strcmp(method, "getCredential") == 0) {
    // parse map { "options": ??? } as the challenge
    std::string challenge = "NO_CHALLENGE";
    if (args && fl_value_get_type(args) == FL_VALUE_TYPE_MAP) {
      FlValue* options_val = fl_value_lookup_string(args, "options");
      if (options_val && fl_value_get_type(options_val) == FL_VALUE_TYPE_STRING) {
        challenge = fl_value_get_string(options_val);
      }
    }
    std::string signature = sign_challenge(challenge);
    g_autoptr(FlValue) result = fl_value_new_string(signature.c_str());
    response = FL_METHOD_RESPONSE(fl_method_success_response_new(result));
  }

  fl_method_call_respond(method_call, response, nullptr);
}

static void flutter_passkey_plugin_class_init(FlutterPasskeyPluginClass* klass) {}
static void flutter_passkey_plugin_init(FlutterPasskeyPlugin* self) {}

// Registration
void flutter_passkey_plugin_register_with_registrar(FlPluginRegistrar* registrar) {
  FlutterPasskeyPlugin* plugin = FLUTTER_PASSKEY_PLUGIN(
      g_object_new(flutter_passkey_plugin_get_type(), nullptr));

  g_autoptr(FlStandardMethodCodec) codec = fl_standard_method_codec_new();
  g_autoptr(FlMethodChannel) channel = fl_method_channel_new(
      fl_plugin_registrar_get_messenger(registrar),
      "flutter_passkey",
      FL_METHOD_CODEC(codec));

  fl_method_channel_set_method_call_handler(channel, handle_method_call, plugin, nullptr);

  g_object_unref(plugin);
}
