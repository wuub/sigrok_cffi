#!/usr/bin/env python
# -*- coding: utf-8 -*-

import threading
from cffi import FFI
ffi = FFI()

glib_cdef = """
typedef int    gint;
typedef gint   gboolean;
typedef unsigned int  guint;
typedef void* gpointer;

typedef struct _GSList GSList;
void g_slist_free (GSList *list);
guint g_slist_length (GSList *list);

struct _GSList
{
  gpointer data;
  GSList *next;
};

typedef ... GVariant;
typedef ... GPollFD;
"""

ffi.cdef(glib_cdef + """

#define SR_OK ...
#define SR_CONF_SAMPLERATE ...
#define SR_DF_LOGIC ...
struct sr_dev_driver {
    char *name;
    char *longname;
    int api_version;
    ...;
};

struct sr_probe {
    /* The index field will go: use g_slist_length(sdi->probes) instead. */
    int index;
    int type;
    gboolean enabled;
    char *name;
    char *trigger;
};

struct sr_datafeed_packet {
    uint16_t type;
    const void *payload;
};

struct sr_datafeed_logic {
    uint64_t length;
    uint16_t unitsize;
    void *data;
};

struct sr_dev_inst {
    struct sr_dev_driver *driver;
    int index;
    int status;
    int inst_type;
    char *vendor;
    char *model;
    char *version;
    GSList *probes;
    void *conn;
    void *priv;
};

typedef ... GIOChannel;
typedef ... sr_receive_data_callback_t;

int sr_init(struct sr_context **ctx);
int sr_exit(struct sr_context *ctx);

int sr_dev_probe_name_set(const struct sr_dev_inst *sdi, int probenum, const char *name);
int sr_dev_probe_enable(const struct sr_dev_inst *sdi, int probenum, gboolean state);
int sr_dev_trigger_set(const struct sr_dev_inst *sdi, int probenum, const char *trigger);
gboolean sr_dev_has_option(const struct sr_dev_inst *sdi, int key);
GSList *sr_dev_list(const struct sr_dev_driver *driver);
int sr_dev_clear(const struct sr_dev_driver *driver);
int sr_dev_open(struct sr_dev_inst *sdi);
int sr_dev_close(struct sr_dev_inst *sdi);

struct sr_dev_driver **sr_driver_list(void);
int sr_driver_init(struct sr_context *ctx, struct sr_dev_driver *driver);
GSList *sr_driver_scan(struct sr_dev_driver *driver, GSList *options);
int sr_config_get(const struct sr_dev_driver *driver, int key, GVariant **data, const struct sr_dev_inst *sdi);
int sr_config_set(const struct sr_dev_inst *sdi, int key, GVariant *data);
int sr_config_list(const struct sr_dev_driver *driver, int key, GVariant **data, const struct sr_dev_inst *sdi);
const struct sr_config_info *sr_config_info_get(int key);
const struct sr_config_info *sr_config_info_name_get(const char *optname);

typedef void (*sr_datafeed_callback_t)(const struct sr_dev_inst *sdi, const struct sr_datafeed_packet *packet, void *cb_data);

int sr_session_load(const char *filename);
struct sr_session *sr_session_new(void);
int sr_session_destroy(void);
int sr_session_dev_remove_all(void);
int sr_session_dev_add(const struct sr_dev_inst *sdi);
// int sr_session_dev_list(GSList **devlist);

int sr_session_datafeed_callback_remove_all(void);
int sr_session_datafeed_callback_add(sr_datafeed_callback_t cb, void *cb_data);

int sr_session_start(void);
int sr_session_run(void);
int sr_session_stop(void);
int sr_session_save(const char *filename, const struct sr_dev_inst *sdi, unsigned char *buf, int unitsize, int units);
// int sr_session_append(const char *filename, unsigned char *buf, int unitsize, int units);
int sr_session_source_add(int fd, int events, int timeout, sr_receive_data_callback_t cb, void *cb_data);
int sr_session_source_add_pollfd(GPollFD *pollfd, int timeout, sr_receive_data_callback_t cb, void *cb_data);
int sr_session_source_add_channel(GIOChannel *channel, int events, int timeout, sr_receive_data_callback_t cb, void *cb_data);
int sr_session_source_remove(int fd);
int sr_session_source_remove_pollfd(GPollFD *pollfd);
int sr_session_source_remove_channel(GIOChannel *channel);

struct sr_input_format **sr_input_list(void);
struct sr_output_format **sr_output_list(void);

char *sr_si_string_u64(uint64_t x, const char *unit);
char *sr_samplerate_string(uint64_t samplerate);
char *sr_period_string(uint64_t frequency);
char *sr_voltage_string(uint64_t v_p, uint64_t v_q);
char **sr_parse_triggerstring(const struct sr_dev_inst *sdi, const char *triggerstring);
int sr_parse_sizestring(const char *sizestring, uint64_t *size);
uint64_t sr_parse_timestring(const char *timestring);
gboolean sr_parse_boolstring(const char *boolstring);
int sr_parse_period(const char *periodstr, uint64_t *p, uint64_t *q);
int sr_parse_voltage(const char *voltstr, uint64_t *p, uint64_t *q);

int sr_package_version_major_get(void);
int sr_package_version_minor_get(void);
int sr_package_version_micro_get(void);
const char *sr_package_version_string_get(void);

int sr_lib_version_current_get(void);
int sr_lib_version_revision_get(void);
int sr_lib_version_age_get(void);
const char *sr_lib_version_string_get(void);

const char *sr_strerror(int error_code);
const char *sr_strerror_name(int error_code);
""")

sigrok = ffi.verify("""
    #include <stdarg.h>
    #include <libsigrok/libsigrok.h>
""",
    libraries=['sigrok'],
    include_dirs=[
        "/usr/include/libusb-1.0/",
        "/usr/include/glib-2.0",
        "/usr/lib/x86_64-linux-gnu/glib-2.0/include/"
    ]
    )

count = 0

if __name__ == '__main__':

    ctx = ffi.new("struct sr_context **")

    def callback_imp(sdi, packet, private_data):
        global count
        count += 1
        if packet.type == sigrok.SR_DF_LOGIC:
            data = ffi.cast("struct sr_datafeed_logic*", packet.payload)

            print(data.length, data.unitsize)
            buf = ffi.buffer(data.data, data.length)
            for read in map(bin, map(ord, buf[:])):
                print(read)
    callback = ffi.callback("sr_datafeed_callback_t", callback_imp)


    assert sigrok.sr_init(ctx) == sigrok.SR_OK
    try:
        dlist = sigrok.sr_driver_list()
        i = 0
        while True:
            driver = dlist[i]
            i += 1
            if driver == ffi.NULL:
                break
            assert sigrok.sr_driver_init(ctx[0], driver) == sigrok.SR_OK
            res = sigrok.sr_driver_scan(driver, ffi.NULL)
            if res != ffi.NULL:
                name = ffi.string(driver[0].name)
                print(name)
                if name == "fx2lafw":
                    sdi = ffi.cast("struct sr_dev_inst*", res.data)
                    print (ffi.string(sdi.vendor))
                    assert sigrok.sr_dev_open(sdi) == sigrok.SR_OK
                    j = 0
                    for idx in range(sigrok.g_slist_length(sdi.probes)):
                        probe = ffi.cast('struct sr_probe*',sdi.probes[idx].data)
                        print (ffi.string(probe.name))
                    session = sigrok.sr_session_new()
                    assert sigrok.sr_session_dev_add(sdi) == sigrok.SR_OK
                    sigrok.sr_session_datafeed_callback_add(callback, ffi.NULL)

                    assert sigrok.sr_session_start() == sigrok.SR_OK
                    def stop():
                        import time
                        time.sleep(1.0)
                        assert sigrok.sr_session_stop() == sigrok.SR_OK
                    threading.Thread(target=stop).start()

                    assert sigrok.sr_session_run() == sigrok.SR_OK
                    print("off")
                    print count
                    sigrok.sr_session_destroy()
            sigrok.g_slist_free(res)

    finally:
        assert sigrok.sr_exit(ctx[0]) == sigrok.SR_OK
