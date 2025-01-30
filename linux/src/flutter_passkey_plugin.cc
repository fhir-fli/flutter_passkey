#include "flutter_passkey_plugin.h"

// For Flutter / GLib
#include <flutter_linux/flutter_linux.h>
#include <gtk/gtk.h>
#include <glib.h>

// For OpenSSL EVP
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/pem.h>
#include <openssl/err.h>

// For standard types
#include <string>
#include <vector>
#include <cstring>

// ---------- Plugin type definition (GObject) ----------
struct _FlutterPasskeyPlugin {
  GObject parent_instance;
};

G_DEFINE_TYPE(FlutterPasskeyPlugin, flutter_passkey_plugin, g_object_get_type())

static void flutter_passkey_plugin_class_init(FlutterPasskeyPluginClass* klass) {}
static void flutter_passkey_plugin_init(FlutterPasskeyPlugin* self) {}

static std::string getKeyPath() {
  const char* dataHome = getenv("XDG_DATA_HOME");
  std::string base;
  if (dataHome && *dataHome) {
    base = dataHome;
  } else {
    // fallback to ~/.local/share
    const char* home = getenv("HOME");
    if (!home) {
      return "/tmp/flutter_passkey_private.pem";
    }
    base = std::string(home) + "/.local/share";
  }
  // possibly mkdir(base + "/flutter_passkey") if needed
  return base + "/passkey_private.pem";
}

// ----------------------------------------------------
// HELPER FUNCTIONS: EVP-based key generation & signing
// ----------------------------------------------------

// Generate an EC key (P-256) using EVP, save to file as PEM
static std::string generate_passkey_evp(const char* privKeyPath) {
  // 1. Create a parameter context for the "EC" key type
  EVP_PKEY_CTX* param_ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
  if (!param_ctx) {
    return "Error: Failed to create param context";
  }
  if (EVP_PKEY_paramgen_init(param_ctx) <= 0) {
    EVP_PKEY_CTX_free(param_ctx);
    return "Error: paramgen_init failed";
  }

  // 2. Set the curve to P-256 (NID_X9_62_prime256v1)
  if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(param_ctx, NID_X9_62_prime256v1) <= 0) {
    EVP_PKEY_CTX_free(param_ctx);
    return "Error: set_ec_paramgen_curve_nid failed";
  }

  // 3. Generate parameters
  EVP_PKEY* params = nullptr;
  if (EVP_PKEY_paramgen(param_ctx, &params) <= 0) {
    EVP_PKEY_CTX_free(param_ctx);
    return "Error: paramgen failed";
  }
  EVP_PKEY_CTX_free(param_ctx);

  // 4. Create a key context from these parameters
  EVP_PKEY_CTX* key_ctx = EVP_PKEY_CTX_new(params, nullptr);
  if (!key_ctx) {
    EVP_PKEY_free(params);
    return "Error: failed to create key_ctx";
  }
  if (EVP_PKEY_keygen_init(key_ctx) <= 0) {
    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(key_ctx);
    return "Error: keygen_init failed";
  }

  // 5. Generate the key
  EVP_PKEY* pkey = nullptr;
  if (EVP_PKEY_keygen(key_ctx, &pkey) <= 0) {
    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(key_ctx);
    return "Error: keygen failed";
  }

  EVP_PKEY_free(params);
  EVP_PKEY_CTX_free(key_ctx);

  // 6. Save the private key to PEM
  FILE* fp = fopen(privKeyPath, "w");
  if (!fp) {
    EVP_PKEY_free(pkey);
    return "Error: couldn't open file for private key";
  }
  if (!PEM_write_PrivateKey(fp, pkey, nullptr, nullptr, 0, nullptr, nullptr)) {
    fclose(fp);
    EVP_PKEY_free(pkey);
    return "Error: writing private key failed";
  }
  fclose(fp);

  // 7. Export the public key as PEM (in-memory)
  BIO* bio = BIO_new(BIO_s_mem());
  if (!bio) {
    EVP_PKEY_free(pkey);
    return "Error: can't create BIO for pubkey";
  }
  if (!PEM_write_bio_PUBKEY(bio, pkey)) {
    BIO_free(bio);
    EVP_PKEY_free(pkey);
    return "Error: writing pubkey PEM failed";
  }

  char* pub_data = nullptr;
  long pub_len = BIO_get_mem_data(bio, &pub_data);
  std::string pubkey_pem(pub_data, pub_len);

  BIO_free(bio);
  EVP_PKEY_free(pkey);

  return pubkey_pem; // Return the public key as a PEM string
}

// Sign data with the EVP key from file. Returns Base64 signature.
static std::string sign_challenge_evp(const std::string& challenge, const char* privKeyPath) {
  // 1. Load the key
  FILE* fp = fopen(privKeyPath, "r");
  if (!fp) {
    return "Error: private key file not found";
  }
  EVP_PKEY* pkey = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
  fclose(fp);

  if (!pkey) {
    return "Error: could not load private key";
  }

  // 2. Create an EVP_MD_CTX for signing
  EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
  if (!mdctx) {
    EVP_PKEY_free(pkey);
    return "Error: EVP_MD_CTX_new failed";
  }

  // 3. Initialize for signing with SHA256
  if (EVP_DigestSignInit(mdctx, nullptr, EVP_sha256(), nullptr, pkey) <= 0) {
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    return "Error: DigestSignInit failed";
  }

  // 4. Provide the data
  if (EVP_DigestSignUpdate(mdctx, challenge.data(), challenge.size()) <= 0) {
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    return "Error: DigestSignUpdate failed";
  }

  // 5. Finalize to get signature length
  size_t sig_len = 0;
  if (EVP_DigestSignFinal(mdctx, nullptr, &sig_len) <= 0) {
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    return "Error: DigestSignFinal (get size) failed";
  }

  // 6. Allocate buffer and get the signature
  std::vector<unsigned char> signature(sig_len);
  if (EVP_DigestSignFinal(mdctx, signature.data(), &sig_len) <= 0) {
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    return "Error: DigestSignFinal (actual) failed";
  }

  EVP_MD_CTX_free(mdctx);
  EVP_PKEY_free(pkey);

  // 7. Convert to base64 with GLib
  gchar* base64_data = g_base64_encode(signature.data(), sig_len);
  std::string base64_sig(base64_data);
  g_free(base64_data);

  return base64_sig;
}

// ----------------------------------------------
// Plugin-level wrappers to call the EVP functions
// ----------------------------------------------
static std::string generate_passkey() {
  std::string path = getKeyPath();
  return generate_passkey_evp(path.c_str());
}

static std::string sign_challenge(const std::string& challenge) {
  std::string path = getKeyPath();
  return sign_challenge_evp(challenge, path.c_str());
}
// ----------------------------------------------
// Flutter method call handler
// ----------------------------------------------
static void handle_method_call(
    FlMethodChannel* channel,
    FlMethodCall* method_call,
    gpointer user_data) {
  // Default response: not implemented
  g_autoptr(FlMethodResponse) response =
      FL_METHOD_RESPONSE(fl_method_not_implemented_response_new());

  const gchar* method = fl_method_call_get_name(method_call);
  FlValue* args = fl_method_call_get_args(method_call);

  if (strcmp(method, "getPlatformVersion") == 0) {
    // Example method
    g_autoptr(FlValue) result =
        fl_value_new_string("Linux Passkey (EVP-based) v1.0");
    response = FL_METHOD_RESPONSE(fl_method_success_response_new(result));

  } else if (strcmp(method, "createCredential") == 0) {
    // Generate key pair, ignoring any 'options'
    std::string pub_key = generate_passkey();
    g_autoptr(FlValue) result = fl_value_new_string(pub_key.c_str());
    response = FL_METHOD_RESPONSE(fl_method_success_response_new(result));

  } else if (strcmp(method, "getCredential") == 0) {
    // Sign a challenge from 'args', if needed
    std::string challenge = "NO_CHALLENGE";
    if (args && fl_value_get_type(args) == FL_VALUE_TYPE_STRING) {
      challenge = fl_value_get_string(args);
    } else if (args && fl_value_get_type(args) == FL_VALUE_TYPE_MAP) {
      // If your Dart code passes {"options": "..."}
      FlValue* opt = fl_value_lookup_string(args, "options");
      if (opt && fl_value_get_type(opt) == FL_VALUE_TYPE_STRING) {
        challenge = fl_value_get_string(opt);
      }
    }
    std::string signature = sign_challenge(challenge);
    g_autoptr(FlValue) result = fl_value_new_string(signature.c_str());
    response = FL_METHOD_RESPONSE(fl_method_success_response_new(result));
  }

  // Send the response
  fl_method_call_respond(method_call, response, nullptr);
}

// ----------------------------------------------
// Plugin registration
// ----------------------------------------------
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
