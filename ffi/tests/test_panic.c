#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>

#include <telio.h>

#define TEST_FUNC(func, ret, info_str, params...) ( \
    {                                               \
        printf("%s\n", info_str);                   \
        __typeof__(ret) res = (func)(params);       \
        assert(ret == res);                         \
    })

bool destroy = false;
bool verbose = false;
char *panic_str = "runtime_panic_test";
char *panic_str_cs = "Panic: runtime_panic_test_call_stack";

static void event_cb(void *ctx, const char *entry)
{
    if (verbose) printf("%s: %s\n", __func__, entry);

    if (strstr(entry, panic_str))
    {
        destroy = true;
    }
}

static void logger_cb(void *ctx, enum telio_log_level lvl, const char *entry)
{
    if (verbose) printf("%s, loglvl %d: %s\n", __func__, lvl, entry);
}

int main(int argc, char **argv)
{
    if ((argc >= 2) && (strcmp("verbose", argv[1]) == 0))
    {
        verbose = true;
    }

    if ((int)geteuid()) {
        printf("You must be root!\n");
        return 1;
    }

    int event_ctx = 0;
    int log_ctx = 0;

    telio *device;
    telio_log_level log_lvl = TELIO_LOG_TRACE;
    telio_event_cb events = {.ctx = (void *)&event_ctx, .cb = event_cb};
    telio_logger_cb logger = {.ctx = (void *)&log_ctx, .cb = logger_cb};
    enum telio_result res = TELIO_RES_OK;
    const char *pub_key = "QKyApX/ewza7QEbC03Yt8t2ghu6nV5/rve/ZJvsecXo=";
    const char *priv_key = telio_generate_secret_key(device);
    char buf[128] = "\0";

    // Run some random init procedure
    TEST_FUNC(telio_new, TELIO_RES_OK, "telio_new", &device, NULL, events, log_lvl, logger);
    TEST_FUNC(telio_start, TELIO_RES_OK, "telio_start", device, priv_key, TELIO_ADAPTER_BORING_TUN);
    TEST_FUNC(telio_connect_to_exit_node, TELIO_RES_OK, "telio_connect_to_exit_node", device, pub_key, "0.0.0.0/0", "1.2.3.4:5678");
    TEST_FUNC(telio_disconnect_from_exit_nodes, TELIO_RES_OK, "telio_disconnect_from_exit_nodes", device);

    sleep(2);
    TEST_FUNC(__telio_generate_thread_panic, TELIO_RES_OK, "__telio_generate_thread_panic", device);
    sleep(2);

    if (destroy)
    {
        TEST_FUNC(telio_destroy_hard, TELIO_RES_OK, "telio_destroy_hard", device);
        destroy = false;
    }

    TEST_FUNC(telio_new, TELIO_RES_OK, "telio_new", &device, NULL, events, log_lvl, logger);
    TEST_FUNC(telio_start, TELIO_RES_OK, "telio_start", device, priv_key, TELIO_ADAPTER_BORING_TUN);

    __telio_generate_stack_panic(device);
    assert(strstr(telio_get_last_error(device), panic_str_cs));

    telio_destroy(device);

    return 0;
}
