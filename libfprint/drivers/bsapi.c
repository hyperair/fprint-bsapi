/*
 * UPEK BSAPI bridge driver for libfprint
 * Copyright (C) 2010 Chow Loong Jin <hyperair@ubuntu.com>
 *
 * This driver hooks onto the proprietary libbsapi.so provided in the UPEK SDK
 * if found. Otherwise, it stays out of the way and lets other drivers take
 * over.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; version
 * 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <dlfcn.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <pthread.h>

#include <bstypes.h>
#include <bserror.h>

#include <glib.h>

#include <fp_internal.h>

#define POLL_MSECS (200)

/* Functions from the libbsapi.so library */
int bsapi_refcnt = 0;
void *bsapi_handle;

static ABS_STATUS (*ABSInitialize)(void) = NULL;
static ABS_STATUS (*ABSTerminate)(void) = NULL;
static ABS_STATUS (*ABSOpen)(const ABS_CHAR *dsn,
                             ABS_CONNECTION *connection) = NULL;
static ABS_STATUS (*ABSClose)(ABS_CONNECTION connection) = NULL;
static ABS_STATUS (*ABSEnumerateDevices)(const char *dsn,
                                         ABS_DEVICE_LIST **device_list) = NULL;
static ABS_STATUS (*ABSGetDeviceProperty)(ABS_CONNECTION connection,
                                          ABS_DWORD property_id,
                                          ABS_DATA **property_data);
static void (*ABSFree)(void *memblock) = NULL;

static ABS_STATUS (*ABSEnroll)(ABS_CONNECTION connection,
                               ABS_OPERATION *operation,
                               ABS_BIR **template,
                               ABS_DWORD flags) = NULL;
static ABS_STATUS (*ABSVerify)(ABS_CONNECTION connection,
                               ABS_OPERATION *operation,
                               ABS_DWORD template_count,
                               ABS_BIR **templates,
                               ABS_LONG *result,
                               ABS_DWORD flags) = NULL;
static ABS_STATUS (*ABSCancelOperation)(ABS_CONNECTION connection,
                                        ABS_DWORD operation_id) = NULL;

#define LOAD_SYMBOL(symbol)                     \
    do {                                        \
        symbol = dlsym (bsapi_handle, #symbol); \
        if (!symbol)                            \
            return 1;                           \
    } while (0);

static int bsapi_ref (void)
{
    BUG_ON (!bsapi_handle && bsapi_refcnt);

    bsapi_refcnt++;

    if (bsapi_handle)
        return 0;

    bsapi_handle = dlopen ("libbsapi.so", RTLD_LAZY);

    if (!bsapi_handle) {
        bsapi_refcnt--;
        return 1;
    }

    LOAD_SYMBOL (ABSInitialize);
    LOAD_SYMBOL (ABSTerminate);
    LOAD_SYMBOL (ABSOpen);
    LOAD_SYMBOL (ABSClose);
    LOAD_SYMBOL (ABSEnumerateDevices);
    LOAD_SYMBOL (ABSGetDeviceProperty);
    LOAD_SYMBOL (ABSFree);
    LOAD_SYMBOL (ABSEnroll);
    LOAD_SYMBOL (ABSVerify);
    LOAD_SYMBOL (ABSCancelOperation);

    ABSInitialize ();

    return 0;
}

static void bsapi_unref (void)
{
    BUG_ON (!bsapi_refcnt || !bsapi_handle);

    if (--bsapi_refcnt == 0) {
        ABSTerminate();

        dlclose (bsapi_handle);
        bsapi_handle = NULL;
        ABSInitialize = NULL;
        ABSTerminate = NULL;
        ABSOpen = NULL;
        ABSClose = NULL;
        ABSEnumerateDevices = NULL;
        ABSGetDeviceProperty = NULL;
        ABSFree = NULL;
        ABSEnroll = NULL;
        ABSVerify = NULL;
    }
}

struct dev_info
{
    uint16_t vendor_id;
    uint16_t product_id;
};

/* Parse the internal DSN string from BSAPI and return usb-ids */
static struct dev_info parse_dsn (const char *dsn)
{
    struct dev_info retval = {0};

    const char *vid_pos, *pid_pos, *dev_pos;

    /* for BSAPI version 3.6 */
    if ((vid_pos = strstr (dsn, "VID_")) && (pid_pos = strstr (dsn, "_PID_"))) {
        char buf[5] = {0};

        strncpy (buf, vid_pos + 4, 4);
        retval.vendor_id = (uint16_t)strtol (buf, 0, 16);

        strncpy (buf, pid_pos + 5, 4);
        retval.product_id = (uint16_t)strtol (buf, 0, 16);
    }

    /* for BSAPI version 4.0 */
    else if ((dev_pos = strstr (dsn, "device=#"))) {
        char buf[5] = {0};

        /* format: device=#NNXXXX_YYYY_*; XXXX:YYYY is the usb-id */
        strncpy (buf, dev_pos + 10, 4);
        retval.vendor_id = (uint16_t)strtol (buf, 0, 16);

        strncpy (buf, dev_pos + 15, 4);
        retval.product_id = (uint16_t)strtol (buf, 0, 16);
    }

    else
        BUG_ON(1);              /* New DSN string format */

    return retval;
}

static char *find_dsn (uint16_t vendor_id, uint16_t product_id)
{
    ABS_DEVICE_LIST *devices = NULL;

    if (ABSEnumerateDevices ("usb", &devices) != ABS_STATUS_OK || !devices)
        return NULL;

    int i;
    char *retval = NULL;
    for (i = 0; i< devices->NumDevices; i++) {
        const char *dsn = devices->List[i].DsnSubString;

        struct dev_info info = parse_dsn (dsn);

        if (info.vendor_id == vendor_id && info.product_id == product_id) {
            retval = g_strdup (dsn);
            break;
        }
    }

    ABSFree (devices);

    return retval;
}

static int discover (struct libusb_device_descriptor *dsc, uint32_t *devtype)
{
    if (bsapi_ref())
        return -1;

    char *dsn = find_dsn (dsc->idVendor, dsc->idProduct);

    if (dsn) {
        free (dsn);
        bsapi_unref();

        return 1;
    }

    bsapi_unref();
    return 0;
}

enum bsapi_mode
{
    BSAPI_MODE_NONE = 0,
    BSAPI_MODE_ENROLL,
    BSAPI_MODE_VERIFY,
};

struct bsapi_dev
{
    ABS_CONNECTION   connection;
    ABS_OPERATION    operation;

    pthread_t        async_thread;

    pthread_mutex_t  mutex;     /* everything below protected by this */

    enum bsapi_mode  mode;
    struct fpi_ssm  *state;

    gboolean         ready;
    ABS_STATUS       result;
    ABS_LONG         verify_result;
    ABS_BIR         *print_data;
};

static void bsapi_msg (const ABS_OPERATION *operation,
                       ABS_DWORD message, void *data)
{
}

static int dev_init (struct fp_dev *dev, unsigned long driver_data)
{
    if (bsapi_ref())
        return -1;

    struct bsapi_dev *bsapidev = NULL;

    /* int r = libusb_claim_interface (dev->udev, 0); */
    /* if (r < 0) */
    /*     return r; */

    struct libusb_device_descriptor desc;
    libusb_get_device_descriptor (libusb_get_device (dev->udev), &desc);
    char *dsn = find_dsn (desc.idVendor, desc.idProduct);

    if (!dsn) {
        fp_err ("Attempted to open device %x:%x with no DSN",
                desc.idVendor, desc.idProduct);
        return -1;
    }

    ABS_CONNECTION c;
    ABS_STATUS s = ABSOpen (dsn, &c);

    if (s != ABS_STATUS_OK) {
        fp_err ("ABSOpen failed, error %d", s);
        return -1;
    }

    bsapidev = g_new0 (struct bsapi_dev, 1);
    bsapidev->connection = c;

    bsapidev->operation.OperationID = 1;
    bsapidev->operation.Context = bsapidev;
    bsapidev->operation.Callback = bsapi_msg;
    bsapidev->operation.Timeout = -1; /* default timeout */

    pthread_mutex_init (&bsapidev->mutex, NULL);

    dev->priv = bsapidev;
    dev->nr_enroll_stages = 1;  /* HACK: ABSEnroll() does all stages at once */

    fpi_drvcb_open_complete (dev, 0);

    return 0;
}

static void dev_exit (struct fp_dev *dev)
{
    struct bsapi_dev *bsapidev = dev->priv;

    ABSClose (bsapidev->connection);
    libusb_release_interface (dev->udev, 0);

    g_free (bsapidev);
    bsapi_unref();

    fpi_drvcb_close_complete (dev);
}

/* Internal functions for handling SSM with enroll/verify */
static void *thread_fn (void *data)
{
    struct fpi_ssm *ssm = data;

    fpi_ssm_next_state (ssm);

    return NULL;
}

static void timer_fn (void *data)
{
    struct fpi_ssm *ssm = data;
    struct bsapi_dev *bsapidev = ssm->dev->priv;

    pthread_mutex_lock (&bsapidev->mutex);
    gboolean ready = bsapidev->ready;
    pthread_mutex_unlock (&bsapidev->mutex);

    if (ready)
        fpi_ssm_next_state (ssm);

    else
        fpi_timeout_add (POLL_MSECS, &timer_fn, ssm);
}

static void cleanup_ssm (struct fpi_ssm *ssm)
{
    struct fp_dev *dev = ssm->dev;
    struct bsapi_dev *bsapidev = dev->priv;

    fpi_ssm_free (ssm);
    bsapidev->state = NULL;

    ABSFree (bsapidev->print_data);
    bsapidev->print_data = NULL;

    bsapidev->mode = BSAPI_MODE_NONE;
}

static void start_ssm (struct fpi_ssm *ssm)
{
    struct bsapi_dev *bsapidev = ssm->dev->priv;

    bsapidev->state = ssm;
    bsapidev->ready = FALSE;
    bsapidev->result = ABS_STATUS_OK;
    bsapidev->print_data = NULL;

    fpi_ssm_start (ssm, &cleanup_ssm);
}

enum enroll_states {
    BEGIN_ENROLL = 0,
    CALL_ENROLL,
    REAP_ENROLL,
    NR_ENROLL_STATES
};

static void enroll_ssm_fn (struct fpi_ssm *ssm)
{
    struct bsapi_dev *bsapidev = ssm->dev->priv;

    BUG_ON (ssm != bsapidev->state);

    switch (ssm->cur_state) {
    case BEGIN_ENROLL:          /* called when starting */
        pthread_create (&bsapidev->async_thread, NULL, &thread_fn, ssm);
        fpi_timeout_add (POLL_MSECS, &timer_fn, ssm);

        fpi_drvcb_enroll_started (ssm->dev, 0);

        break;

    case CALL_ENROLL: {         /* called on async_thread */
        ABS_BIR *template = NULL;
        ABS_STATUS s = ABSEnroll (bsapidev->connection, &bsapidev->operation,
                                  &template, 0);

        pthread_mutex_lock (&bsapidev->mutex);

        bsapidev->ready = TRUE; /* signals to timer to poke ssm */
        bsapidev->result = s;
        bsapidev->print_data = template;

        pthread_mutex_unlock (&bsapidev->mutex);

        break;
    }

    case REAP_ENROLL:           /* called from timer_fn */
        pthread_join (bsapidev->async_thread, NULL);
        /* thread finished, no need to lock */

        if (ssm->dev->state == DEV_STATE_ENROLL_STOPPING)
            fpi_drvcb_enroll_stopped (ssm->dev);

        else if (bsapidev->result == ABS_STATUS_OK) {
            struct fp_print_data *print_data =
                fpi_print_data_new (ssm->dev,
                                    bsapidev->print_data->Header.Length);

            memcpy (print_data->data, bsapidev->print_data,
                    bsapidev->print_data->Header.Length);

            fpi_drvcb_enroll_stage_completed (ssm->dev, FP_ENROLL_COMPLETE,
                                              print_data, NULL);

        } else
            fpi_drvcb_enroll_stage_completed (ssm->dev, -1,
                                              NULL, NULL);

        /* A callback may have called enroll_stop() */
        if (ssm->dev->state == DEV_STATE_ENROLL_STOPPING)
            fpi_drvcb_enroll_stopped (ssm->dev);

        fpi_ssm_next_state (ssm);
        break;
    }
}

static int enroll_start (struct fp_dev *dev)
{
    struct bsapi_dev *bsapidev = dev->priv;

    if (bsapidev->mode != BSAPI_MODE_NONE)
        return -EBUSY;

    bsapidev->mode = BSAPI_MODE_ENROLL;

    start_ssm (fpi_ssm_new (dev, &enroll_ssm_fn, NR_ENROLL_STATES));

    return 0;
}

static int enroll_stop (struct fp_dev *dev)
{
    struct bsapi_dev *bsapidev = dev->priv;

    if (bsapidev->mode != BSAPI_MODE_ENROLL) {
        fpi_drvcb_enroll_stopped (dev);
        return 0;
    }

    ABSCancelOperation (bsapidev->connection, bsapidev->operation.OperationID);

    return 0;
}

enum verify_states {
    BEGIN_VERIFY = 0,
    CALL_VERIFY,
    REAP_VERIFY
};

static void verify_ssm_fn (struct fpi_ssm *ssm)
{
    struct bsapi_dev *bsapidev = ssm->dev->priv;

    switch (ssm->cur_state)
    {
    case BEGIN_VERIFY:
        pthread_create (&bsapidev->async_thread, NULL, &thread_fn, ssm);
        fpi_timeout_add (POLL_MSECS, &timer_fn, ssm);

        fpi_drvcb_verify_started (ssm->dev, 0);

        break;

    case CALL_VERIFY: {         /* on async_thread */
        ABS_BIR *bir = (ABS_BIR *)ssm->dev->verify_data->data;
        BUG_ON (bir->Header.Length != ssm->dev->verify_data->length);

        ABS_LONG verify_result = -1;
        ABS_STATUS result = ABSVerify (bsapidev->connection,
                                       &bsapidev->operation,
                                       1, &bir, &verify_result, 0);

        pthread_mutex_lock (&bsapidev->mutex);

        bsapidev->result = result;
        bsapidev->verify_result = verify_result;
        bsapidev->ready = TRUE;

        pthread_mutex_unlock (&bsapidev->mutex);

        break;
    }

    case REAP_VERIFY:
        if (ssm->dev->state == DEV_STATE_VERIFY_STOPPING)
            fpi_drvcb_verify_stopped (ssm->dev);

        else
            fpi_drvcb_report_verify_result (ssm->dev,
                                            bsapidev->verify_result != -1 ?
                                            FP_VERIFY_MATCH :
                                            FP_VERIFY_NO_MATCH,
                                            NULL);

        if (ssm->dev->state == DEV_STATE_VERIFY_STOPPING)
            fpi_drvcb_verify_stopped (ssm->dev);

        fpi_ssm_next_state (ssm);
        break;
    }
}

static int verify_start (struct fp_dev *dev)
{
    struct bsapi_dev *bsapidev = dev->priv;
    if (bsapidev->mode != BSAPI_MODE_NONE)
        return -EBUSY;

    bsapidev->mode = BSAPI_MODE_VERIFY;

    start_ssm (fpi_ssm_new (dev, &verify_ssm_fn, NR_ENROLL_STATES));

    return 0;
}

static int verify_stop (struct fp_dev *dev, gboolean iterating)
{
    struct bsapi_dev *bsapidev = dev->priv;
    if (bsapidev->mode != BSAPI_MODE_VERIFY) {
        fpi_drvcb_verify_stopped (dev);
        return 0;
    }

    ABSCancelOperation (bsapidev->connection, bsapidev->operation.OperationID);

    return 0;
}


/* TODO: Complete listing of usb devices here */
static const struct usb_id id_table[] = {
    { .vendor = 0x147e, .product = 0x1002 },
    { 0, 0, 0, },
};

struct fp_driver bsapi_driver = {
	.id = 11,
	.name = "bsapi",
	.full_name = "UPEK libbsapi bridge",
	.id_table = id_table,
	.scan_type = FP_SCAN_TYPE_SWIPE,
        .discover = discover,
	.open = dev_init,
	.close = dev_exit,
	.enroll_start = enroll_start,
	.enroll_stop = enroll_stop,
	.verify_start = verify_start,
	.verify_stop = verify_stop,
};

