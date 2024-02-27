#ifndef TELIO_H
#define TELIO_H

/* Generated with cbindgen:0.24.3 */

/* Warning, this file is autogenerated by cbindgen. Don't modify this manually. */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * Possible adapters.
 */
typedef enum telio_adapter_type {
  /**
   * Userland rust implementation.
   */
  TELIO_ADAPTER_BORING_TUN,
  /**
   * Linux in-kernel WireGuard implementation
   */
  TELIO_ADAPTER_LINUX_NATIVE_TUN,
  /**
   * WireguardGo implementation
   */
  TELIO_ADAPTER_WIREGUARD_GO_TUN,
  /**
   * WindowsNativeWireguardNt implementation
   */
  TELIO_ADAPTER_WINDOWS_NATIVE_TUN,
} telio_adapter_type;

/**
 * Possible log levels.
 */
typedef enum telio_log_level {
  TELIO_LOG_CRITICAL = 1,
  TELIO_LOG_ERROR = 2,
  TELIO_LOG_WARNING = 3,
  TELIO_LOG_INFO = 4,
  TELIO_LOG_DEBUG = 5,
  TELIO_LOG_TRACE = 6,
} telio_log_level;

typedef enum telio_result {
  /**
   * Operation was successful.
   */
  TELIO_RES_OK = 0,
  /**
   * Operation resulted to unknown error.
   */
  TELIO_RES_ERROR = 1,
  /**
   * Cannot parse key as base64 string.
   */
  TELIO_RES_INVALID_KEY = 2,
  /**
   * Cannot parse configuration.
   */
  TELIO_RES_BAD_CONFIG = 3,
  /**
   * Cannot lock a mutex.
   */
  TELIO_RES_LOCK_ERROR = 4,
  /**
   * Cannot parse a string.
   */
  TELIO_RES_INVALID_STRING = 5,
  /**
   * The device is already started.
   */
  TELIO_RES_ALREADY_STARTED = 6,
} telio_result;

typedef struct telio telio;

typedef void (*telio_event_fn)(void*, const char*);

/**
 * Event callback
 */
typedef struct telio_event_cb {
  /**
   * Context to pass to callback.
   * User must ensure safe access of this var from multithreaded context.
   */
  void *ctx;
  /**
   * Function to be called
   */
  telio_event_fn cb;
} telio_event_cb;

typedef void (*telio_logger_fn)(void*, enum telio_log_level, const char*);

/**
 * Logging callback
 */
typedef struct telio_logger_cb {
  /**
   * Context to pass to callback.
   * User must ensure safe access of this var from multithreaded context.
   */
  void *ctx;
  /**
   * Function to be called
   */
  telio_logger_fn cb;
} telio_logger_cb;

#if defined(__ANDROID__)
typedef void (*telio_protect_fn)(void*, int32_t);
#endif

#if defined(__ANDROID__)
/**
 * Android protect fd from VPN callback
 */
typedef struct telio_protect_cb {
  /**
   * Context to pass to callback.
   * User must ensure safe access of this var from multithreaded context.
   */
  void *ctx;
  /**
   * Function to be called
   */
  telio_protect_fn cb;
} telio_protect_cb;
#endif

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

extern void fortify_source(void);

/**
 * Create new telio library instance
 * # Parameters
 * - `events`:     Events callback
 * - `features`:   JSON string of enabled features
 * - `log_level`:  Log level
 * - `logger`:     Logging callback
 */
enum telio_result telio_new(struct telio **dev,
                            const char *features,
                            struct telio_event_cb events,
                            enum telio_log_level log_level,
                            struct telio_logger_cb logger);

#if defined(__ANDROID__)
/**
 * Initialize OS certificate store, should be called only once. Without call to telio_init_cert_store
 * telio will not be able to verify https certificates in the system certificate store.
 * # Params
 * - `env`:    see https://developer.android.com/training/articles/perf-jni#javavm-and-jnienv
 * - `ctx`:    see https://developer.android.com/reference/android/content/Context
 */
enum telio_result telio_init_cert_store(JNIEnv *env,
                                        jobject ctx);
#endif

#if defined(__ANDROID__)
/**
 * Create new telio library instance
 * # Parameters
 * - `events`:     Events callback
 * - `features`:   JSON string of enabled features
 * - `log_level`:  Log level
 * - `logger`:     Logging callback
 * - `protect`:    Callback executed after exit-node connect (for VpnService::protectFromVpn())
 */
enum telio_result telio_new_with_protect(struct telio **dev,
                                         const char *features,
                                         struct telio_event_cb events,
                                         enum telio_log_level log_level,
                                         struct telio_logger_cb logger,
                                         struct telio_protect_cb protect);
#endif

/**
 * Completely stop and uninit telio lib.
 */
void telio_destroy(struct telio *dev);

/**
 * Explicitly deallocate telio object and shutdown async rt.
 */
enum telio_result telio_destroy_hard(struct telio *dev);

/**
 * Get default recommended adapter type for platform.
 */
enum telio_adapter_type telio_get_default_adapter(void);

/**
 * Start telio with specified adapter.
 *
 * Adapter will attempt to open its own tunnel.
 */
enum telio_result telio_start(const struct telio *dev,
                              const char *private_key,
                              enum telio_adapter_type adapter);

/**
 * Start telio with specified adapter and name.
 *
 * Adapter will attempt to open its own tunnel.
 */
enum telio_result telio_start_named(const struct telio *dev,
                                    const char *private_key,
                                    enum telio_adapter_type adapter,
                                    const char *name);

#if !defined(_WIN32)
/**
 * Start telio device with specified adapter and already open tunnel.
 *
 * Telio will take ownership of tunnel , and close it on stop.
 *
 * # Parameters
 * - `private_key`: base64 encoded private_key.
 * - `adapter`: Adapter type.
 * - `tun`: A valid filedescriptor to tun device.
 *
 */
enum telio_result telio_start_with_tun(const struct telio *dev,
                                       const char *private_key,
                                       enum telio_adapter_type adapter,
                                       int tun);
#endif

/**
 * Stop telio device.
 */
enum telio_result telio_stop(const struct telio *dev);

/**
 * get device luid.
 */
uint64_t telio_get_adapter_luid(const struct telio *dev);

/**
 * Sets private key for started device.
 *
 * If private_key is not set, device will never connect.
 *
 * # Parameters
 * - `private_key`: Base64 encoded WireGuard private key, must not be NULL.
 *
 */
enum telio_result telio_set_private_key(const struct telio *dev, const char *private_key);

char *telio_get_private_key(const struct telio *dev);

#if defined(__linux__)
/**
 * Sets fmark for started device.
 *
 * # Parameters
 * - `fwmark`: unsigned 32-bit integer
 *
 */
enum telio_result telio_set_fwmark(const struct telio *dev, unsigned int fwmark);
#endif

/**
 * Notify telio with network state changes.
 *
 * # Parameters
 * - `network_info`: Json encoded network sate info.
 *                   Format to be decided, pass empty string for now.
 */
enum telio_result telio_notify_network_change(const struct telio *dev, const char *network_info);

/**
 * Wrapper for `telio_connect_to_exit_node_with_id` that doesn't take an identifier
 */
enum telio_result telio_connect_to_exit_node(const struct telio *dev,
                                             const char *public_key,
                                             const char *allowed_ips,
                                             const char *endpoint);

/**
 * Connects to an exit node. (VPN if endpoint is not NULL, Peer if endpoint is NULL)
 *
 * Routing should be set by the user accordingly.
 *
 * # Parameters
 * - `identifier`: String that identifies the exit node, will be generated if null is passed.
 * - `public_key`: Base64 encoded WireGuard public key for an exit node.
 * - `allowed_ips`: Semicolon separated list of subnets which will be routed to the exit node.
 *                  Can be NULL, same as "0.0.0.0/0".
 * - `endpoint`: An endpoint to an exit node. Can be NULL, must contain a port.
 *
 * # Examples
 *
 * ```c
 * // Connects to VPN exit node.
 * telio_connect_to_exit_node_with_id(
 *     "5e0009e1-75cf-4406-b9ce-0cbb4ea50366",
 *     "QKyApX/ewza7QEbC03Yt8t2ghu6nV5/rve/ZJvsecXo=",
 *     "0.0.0.0/0", // Equivalent
 *     "1.2.3.4:5678"
 * );
 *
 * // Connects to VPN exit node, with specified allowed_ips.
 * telio_connect_to_exit_node_with_id(
 *     "5e0009e1-75cf-4406-b9ce-0cbb4ea50366",
 *     "QKyApX/ewza7QEbC03Yt8t2ghu6nV5/rve/ZJvsecXo=",
 *     "100.100.0.0/16;10.10.23.0/24",
 *     "1.2.3.4:5678"
 * );
 *
 * // Connect to exit peer via DERP
 * telio_connect_to_exit_node_with_id(
 *     "5e0009e1-75cf-4406-b9ce-0cbb4ea50366",
 *     "QKyApX/ewza7QEbC03Yt8t2ghu6nV5/rve/ZJvsecXo=",
 *     "0.0.0.0/0",
 *     NULL
 * );
 * ```
 *
 */
enum telio_result telio_connect_to_exit_node_with_id(const struct telio *dev,
                                                     const char *identifier,
                                                     const char *public_key,
                                                     const char *allowed_ips,
                                                     const char *endpoint);

/**
 * Connects to the VPN exit node with post quantum tunnel
 *
 * Routing should be set by the user accordingly.
 *
 * # Parameters
 * - `identifier`: String that identifies the exit node, will be generated if null is passed.
 * - `public_key`: Base64 encoded WireGuard public key for an exit node.
 * - `allowed_ips`: Semicolon separated list of subnets which will be routed to the exit node.
 *                  Can be NULL, same as "0.0.0.0/0".
 * - `endpoint`: An endpoint to an exit node. Must contain a port.
 *
 * # Examples
 *
 * ```c
 * // Connects to VPN exit node.
 * telio_connect_to_exit_node_postquantum(
 *     "5e0009e1-75cf-4406-b9ce-0cbb4ea50366",
 *     "QKyApX/ewza7QEbC03Yt8t2ghu6nV5/rve/ZJvsecXo=",
 *     "0.0.0.0/0", // Equivalent
 *     "1.2.3.4:5678"
 * );
 *
 * // Connects to VPN exit node, with specified allowed_ips.
 * telio_connect_to_exit_node_postquantum(
 *     "5e0009e1-75cf-4406-b9ce-0cbb4ea50366",
 *     "QKyApX/ewza7QEbC03Yt8t2ghu6nV5/rve/ZJvsecXo=",
 *     "100.100.0.0/16;10.10.23.0/24",
 *     "1.2.3.4:5678"
 * );
 * ```
 *
 */
enum telio_result telio_connect_to_exit_node_postquantum(const struct telio *dev,
                                                         const char *identifier,
                                                         const char *public_key,
                                                         const char *allowed_ips,
                                                         const char *endpoint);

/**
 * Enables magic DNS if it was not enabled yet,
 *
 * Routing should be set by the user accordingly.
 *
 * # Parameters
 * - 'forward_servers': JSON array of DNS servers to route the requests trough.
 *                      Cannot be NULL, accepts an empty array of servers.
 * # Examples
 *
 * ```c
 * // Enable magic dns with some forward servers
 * telio_enable_magic_dns("[\"1.1.1.1\", \"8.8.8.8\"]");
 *
 * // Enable magic dns with no forward server
 * telio_enable_magic_dns("[\"\"]");
 * ```
 */
enum telio_result telio_enable_magic_dns(const struct telio *dev, const char *forward_servers);

/**
 * Disables magic DNS if it was enabled.
 */
enum telio_result telio_disable_magic_dns(const struct telio *dev);

/**
 * Disconnects from specified exit node.
 *
 * # Parameters
 * - `public_key`: Base64 encoded WireGuard public key for exit node.
 *
 */
enum telio_result telio_disconnect_from_exit_node(const struct telio *dev, const char *public_key);

/**
 * Disconnects from all exit nodes with no parameters required.
 */
enum telio_result telio_disconnect_from_exit_nodes(const struct telio *dev);

/**
 * Enables meshnet if it is not enabled yet.
 * In case meshnet is enabled, this updates the peer map with the specified one.
 *
 * # Parameters
 * - `cfg`: Output of GET /v1/meshnet/machines/{machineIdentifier}/map
 *
 */
enum telio_result telio_set_meshnet(const struct telio *dev, const char *cfg);

/**
 * Disables the meshnet functionality by closing all the connections.
 */
enum telio_result telio_set_meshnet_off(const struct telio *dev);

char *telio_generate_secret_key(const struct telio *_dev);

char *telio_generate_public_key(const struct telio *_dev, const char *secret);

char *telio_get_version_tag(void);

char *telio_get_commit_sha(void);

char *telio_get_status_map(const struct telio *dev);

/**
 * Get last error's message length, including trailing null
 */
char *telio_get_last_error(const struct telio *_dev);

/**
 * For testing only.
 */
enum telio_result __telio_generate_stack_panic(const struct telio *dev);

/**
 * For testing only.
 */
enum telio_result __telio_generate_thread_panic(const struct telio *dev);

void __telio_force_export(enum telio_result,
                          enum telio_adapter_type,
                          struct telio_event_cb,
                          struct telio_logger_cb,
                          struct telio_protect_cb);

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus

#endif /* TELIO_H */
