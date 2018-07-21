/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * ratp-barebox-cli - Minimal libratp-barebox tester
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2017 Zodiac Inflight Innovations
 * Copyright (C) 2017 Aleksander Morgado <aleksander@aleksander.es>
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <getopt.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <termios.h>
#include <assert.h>

#include <ratp.h>
#include <ratp-barebox.h>

#define PROGRAM_NAME    "ratp-barebox-cli"
#define PROGRAM_VERSION PACKAGE_VERSION

#define DEFAULT_TIMEOUT_MS 5000

/******************************************************************************/

static unsigned long main_tid;

static double
current_timestamp (void)
{
    struct timespec now;

    clock_gettime (CLOCK_MONOTONIC, &now);
    return (now.tv_sec + now.tv_nsec / 1E9);
}

static void
ratp_log_handler (ratp_log_level_t  level,
                  unsigned long     tid,
                  const char       *message)
{
    printf ("%.6lf [ratp %015lu] %s: %s\n", current_timestamp (), tid == main_tid ? 0 : tid, ratp_log_level_str (level), message);
}

static void
ratp_barebox_log_handler (ratp_barebox_log_level_t  level,
                          unsigned long             tid,
                          const char               *message)
{
    printf ("%.6lf [ratp %015lu] %s: %s\n", current_timestamp (), tid == main_tid ? 0 : tid, ratp_barebox_log_level_str (level), message);
}

static char *
strhex (const void *mem,
        size_t      size,
        const char *delimiter)
{
    const uint8_t *data = mem;
    size_t         i, j, new_str_length, delimiter_length;
    char          *new_str;

    assert (size > 0);

    /* Allow delimiters of arbitrary sizes, including 0 */
    delimiter_length = (delimiter ? strlen (delimiter) : 0);

    /* Get new string length. If input string has N bytes, we need:
     * - 1 byte for last NUL char
     * - 2N bytes for hexadecimal char representation of each byte...
     * - N-1 times the delimiter length
     * So... e.g. if delimiter is 1 byte,  a total of:
     *   (1+2N+N-1) = 3N bytes are needed...
     */
    new_str_length =  1 + (2 * size) + ((size - 1) * delimiter_length);

    /* Allocate memory for new array and initialize contents to NUL */
    new_str = calloc (new_str_length, 1);

    /* Print hexadecimal representation of each byte... */
    for (i = 0, j = 0; i < size; i++, j += (2 + delimiter_length)) {
        /* Print character in output string... */
        snprintf (&new_str[j], 3, "%02x", data[i]);
        /* And if needed, add separator */
        if (delimiter_length && i != (size - 1) )
            strncpy (&new_str[j + 2], delimiter, delimiter_length);
    }

    /* Set output string */
    return new_str;
}

static uint8_t *
hexstr (const char *str,
        const char *delimiter,
        size_t     *out_size)
{
    char byte[3] = { 0x00, 0x00, 0x00 };
    uint8_t *data;
    size_t i, j, delimiter_length, str_length, data_size, byte_length;

    str_length = strlen (str);

    /* Allow delimiters of arbitrary sizes, including 0 */
    delimiter_length = (delimiter ? strlen (delimiter) : 0);

    /* 1 byte is represented by 2 hex digits plus a delimiter afterwards, except
     * for the last byte which doesn't have delimiter */
    byte_length = 2 + delimiter_length;

    /* Be a bit strict about the input format for now */
    if (((str_length + delimiter_length) % byte_length) != 0)
        return NULL;

    data_size = (str_length + delimiter_length) / (byte_length);
    data = calloc (data_size, 1);

    for (i = 0, j = 0; i < data_size; i++, j += (2 + delimiter_length)) {
        /* 2 hex digits */
        if (!isxdigit (str[j]) || !isxdigit (str[j + 1]))
            break;
        /* and a delimiter except for the last one */
        if ((i < (data_size - 1)) && delimiter_length && (strncmp (&str[j + 2], delimiter, delimiter_length) != 0))
            break;

        byte[0] = str[j];
        byte[1] = str[j + 1];

        data[i] = (uint8_t) strtoul (byte, NULL, 16);
    }

    if (i != data_size) {
        free (data);
        return NULL;
    }

    *out_size = data_size;
    return data;
}

/******************************************************************************/

struct baudrate_num_s {
    speed_t       baudrate;
    unsigned long num;
};

static const struct baudrate_num_s baudrate_num[] = {
    {  B9600,      9600 },
    {  B19200,    19200 },
    {  B38400,    38400 },
    {  B57600,    57600 },
    {  B115200,  115200 },
    {  B230400,  230400 },
    {  B460800,  460800 },
    {  B500000,  500000 },
    {  B576000,  576000 },
    {  B921600,  921600 },
    { B1000000, 1000000 },
    { B1152000, 1152000 },
    { B1500000, 1500000 },
    { B2000000, 2000000 },
    { B2500000, 2500000 },
    { B3000000, 3000000 },
    { B3500000, 3500000 },
    { B4000000, 4000000 },
};

static speed_t
baudrate_from_num (unsigned long num)
{
    int i;

    for (i = 0; i < (sizeof (baudrate_num) / sizeof (baudrate_num[0])); i++) {
        if (baudrate_num[i].num == num)
            return baudrate_num[i].baudrate;
    }

    return B0;
}

/******************************************************************************/

static bool volatile quit_requested;

static void
sig_handler (int signo)
{
    quit_requested = true;
}

/******************************************************************************/

static int
run_ping (ratp_link_t *ratp,
          unsigned int timeout,
          bool quiet)
{
    ratp_status_t st;

    if ((st = ratp_link_active_open_sync (ratp, 5000)) != RATP_STATUS_OK) {
        fprintf (stderr, "error: couldn't actively open link: %s\n", ratp_status_str (st));
        return -1;
    }

    if (!quiet)
        printf ("Sending PING...\n");
    if ((st = ratp_barebox_link_ping (ratp, timeout)) != RATP_STATUS_OK) {
        fprintf (stderr, "error: couldn't send PING: %s\n", ratp_status_str (st));
        return -1;
    }
    if (!quiet)
        printf ("PONG received...\n");

    if ((st = ratp_link_close_sync (ratp, 1000)) != RATP_STATUS_OK)
        fprintf (stderr, "warning: couldn't close link: %s\n", ratp_status_str (st));

    return 0;
}

static int
run_command (ratp_link_t *ratp,
             const char  *command,
             unsigned int timeout,
             bool quiet)
{
    ratp_status_t st;
    uint32_t      errno_result = 0;
    char         *stdout_result = NULL;

    if ((st = ratp_link_active_open_sync (ratp, 5000)) != RATP_STATUS_OK) {
        fprintf (stderr, "error: couldn't actively open link: %s\n", ratp_status_str (st));
        return -1;
    }

    if (!quiet)
        printf ("Sending command: %s\n", command);
    if ((st = ratp_barebox_link_command (ratp, timeout, command, &errno_result, &stdout_result)) != RATP_STATUS_OK) {
        fprintf (stderr, "error: couldn't send command: %s\n", ratp_status_str (st));
        return -1;
    }
    if (!quiet)
        printf ("Received response (errno %s):\n", strerror (errno_result));
    printf ("%s%c", stdout_result ? stdout_result : "", quiet ? '\0' : '\n');

    if ((st = ratp_link_close_sync (ratp, 1000)) != RATP_STATUS_OK)
        fprintf (stderr, "warning: couldn't close link: %s\n", ratp_status_str (st));

    return errno_result;
}

static int
run_getenv (ratp_link_t *ratp,
            const char  *env_name,
            unsigned int timeout,
            bool quiet)
{
    ratp_status_t  st;
    char          *env_value = NULL;

    if ((st = ratp_link_active_open_sync (ratp, 5000)) != RATP_STATUS_OK) {
        fprintf (stderr, "error: couldn't actively open link: %s\n", ratp_status_str (st));
        return -1;
    }

    if (!quiet)
        printf ("Sending getenv request: %s\n", env_name);
    if ((st = ratp_barebox_link_getenv (ratp, timeout, env_name, &env_value)) != RATP_STATUS_OK) {
        fprintf (stderr, "error: couldn't getenv: %s\n", ratp_status_str (st));
        return -1;
    }
    if (!quiet)
        printf ("%s: %s\n", env_name, env_value);
    else
        printf ("%s", env_value);

    if ((st = ratp_link_close_sync (ratp, 1000)) != RATP_STATUS_OK)
        fprintf (stderr, "warning: couldn't close link: %s\n", ratp_status_str (st));

    return 0;
}

static int
run_md (ratp_link_t  *ratp,
        const char   *action_args,
        unsigned int  timeout,
        bool          quiet)
{
    ratp_status_t  st;
    uint8_t       *out = NULL;
    uint16_t       out_size = 0;
    char          *out_hex = NULL;
    int            ret = -1;
    char          *aux, *aux1, *aux2;
    const char    *path;
    unsigned int   start;
    unsigned int   size;

    aux = strdup (action_args);
    if (!aux)
        goto out;

    aux1 = strchr (aux, ',');
    if (!aux1) {
        fprintf (stderr, "error: only one field given in --md arguments\n");
        goto out;
    }
    *aux1 = '\0';
    aux1++;

    aux2 = strchr (aux1, ',');
    if (!aux2) {
        fprintf (stderr, "error: only two fields given in --md arguments\n");
        goto out;
    }
    *aux2 = '\0';
    aux2++;

    path = aux;
    if (!path[0]) {
        fprintf (stderr, "error: empty memory device file path given\n");
        goto out;
    }

    start = strtoul (aux1, NULL, 16);

    size = strtoul (aux2, NULL, 10);
    if (!size) {
        fprintf (stderr, "error: no size requested\n");
        goto out;
    }

    if ((st = ratp_link_active_open_sync (ratp, 5000)) != RATP_STATUS_OK) {
        fprintf (stderr, "error: couldn't actively open link: %s\n", ratp_status_str (st));
        goto out;
    }

    if (!quiet)
        printf ("Sending md request: read '%s': 0x%04x (+%u bytes)\n", path, start, size);
    if ((st = ratp_barebox_link_md (ratp, timeout, path, start, size, &out, &out_size)) != RATP_STATUS_OK) {
        fprintf (stderr, "error: couldn't md: %s\n", ratp_status_str (st));
        ret = -1;
        goto out_close;
    }

    out_hex = strhex (out, out_size, ":");
    if (!out_hex) {
        fprintf (stderr, "error: couldn't hex print returned contents\n");
        ret = -2;
        goto out_close;
    }
    printf ("%s\n", out_hex);
    ret = 0;

out_close:

    if ((st = ratp_link_close_sync (ratp, 1000)) != RATP_STATUS_OK)
        fprintf (stderr, "warning: couldn't close link: %s\n", ratp_status_str (st));

out:
    free (out);
    free (out_hex);
    free (aux);

    return ret;
}

static int
run_mw (ratp_link_t  *ratp,
        const char   *action_args,
        unsigned int  timeout,
        bool          quiet)
{
    ratp_status_t  st;
    uint8_t       *data = NULL;
    size_t         data_size = 0;
    int            ret = -1;
    char          *aux, *aux1, *aux2;
    const char    *path;
    unsigned int   addr;
    uint16_t       written;

    aux = strdup (action_args);
    if (!aux)
        goto out;

    aux1 = strchr (aux, ',');
    if (!aux1) {
        fprintf (stderr, "error: only one field given in --mw arguments\n");
        goto out;
    }
    *aux1 = '\0';
    aux1++;

    aux2 = strchr (aux1, ',');
    if (!aux2) {
        fprintf (stderr, "error: only two fields given in --mw arguments\n");
        goto out;
    }
    *aux2 = '\0';
    aux2++;

    path = aux;
    if (!path[0]) {
        fprintf (stderr, "error: empty memory device file path given\n");
        goto out;
    }

    addr = strtoul (aux1, NULL, 16);

    data = hexstr (aux2, ":", &data_size);
    if (!data) {
        fprintf (stderr, "error: couldn't process input data\n");
        goto out;
    }

    if (data_size > 0xFFFF) {
        fprintf (stderr, "error: too much data\n");
        goto out;
    }

    if ((st = ratp_link_active_open_sync (ratp, 5000)) != RATP_STATUS_OK) {
        fprintf (stderr, "error: couldn't actively open link: %s\n", ratp_status_str (st));
        goto out;
    }

    if (!quiet)
        printf ("Sending mw request: write '%s': 0x%04x (+%zu bytes)\n", path, addr, data_size);
    if ((st = ratp_barebox_link_mw (ratp, timeout, path, addr, data, (uint16_t) data_size, &written)) != RATP_STATUS_OK) {
        fprintf (stderr, "error: couldn't mw: %s\n", ratp_status_str (st));
        ret = -1;
        goto out_close;
    }

    printf ("%hu/%zu bytes written\n", written, data_size);
    ret = 0;

out_close:

    if ((st = ratp_link_close_sync (ratp, 1000)) != RATP_STATUS_OK)
        fprintf (stderr, "warning: couldn't close link: %s\n", ratp_status_str (st));

out:
    free (data);
    free (aux);

    return ret;
}

static int
run_i2c_read (ratp_link_t  *ratp,
              const char   *action_args,
              unsigned int  timeout,
              bool          quiet)
{
    ratp_status_t  st;
    uint8_t       *out = NULL;
    uint16_t       out_size = 0;
    char          *out_hex = NULL;
    int            ret = -1;
    char          *aux0, *aux1, *aux2, *aux3;
    unsigned long  bus;
    unsigned long  addr;
    unsigned long  reg;
    unsigned long  size;
    int            reglen;
    ratp_barebox_link_i2c_flag_t flags = RATP_BAREBOX_LINK_I2C_FLAG_NONE;

    aux0 = strdup (action_args);
    if (!aux0)
        goto out;

    aux1 = strchr (aux0, ',');
    if (!aux1) {
        fprintf (stderr, "error: only one field given in --i2c-read arguments\n");
        goto out;
    }
    *aux1 = '\0';
    aux1++;

    aux2 = strchr (aux1, ',');
    if (!aux2) {
        fprintf (stderr, "error: only two fields given in --i2c-read arguments\n");
        goto out;
    }
    *aux2 = '\0';
    aux2++;

    aux3 = strchr (aux2, ',');
    if (!aux3) {
        fprintf (stderr, "error: only three fields given in --i2c-read arguments\n");
        goto out;
    }
    *aux3 = '\0';
    aux3++;

    bus = strtoul (aux0, NULL, 16);
    if (bus > 0xFF) {
        fprintf (stderr, "error: invalid bus number\n");
        goto out;
    }

    addr = strtoul (aux1, NULL, 16);
    if (addr > 0x7F) {
        fprintf (stderr, "error: invalid address\n");
        goto out;
    }

    if (aux2[0] == '\0') {
        reg = 0;
        flags |= RATP_BAREBOX_LINK_I2C_FLAG_MASTER_MODE;
    } else {
        if (strncmp (aux2, "0x", 2) == 0)
            aux2 += 2;
        reglen = strlen (aux2);
        if (reglen != 2 && reglen != 4) {
            fprintf (stderr, "error: invalid register: must be given either as 1 byte (0xAB) or 2 bytes (0xABCD)\n");
            goto out;
        }
        reg = strtoul (aux2, NULL, 16);
        assert (reglen <= 0xFFFF);
        if (reglen == 4)
            flags |= RATP_BAREBOX_LINK_I2C_FLAG_WIDE_ADDRESS;
    }

    size = strtoul (aux3, NULL, 10);
    if (!size) {
        fprintf (stderr, "error: no size requested\n");
        goto out;
    }

    if ((st = ratp_link_active_open_sync (ratp, 5000)) != RATP_STATUS_OK) {
        fprintf (stderr, "error: couldn't actively open link: %s\n", ratp_status_str (st));
        goto out;
    }

    if (!quiet)
        printf ("Sending i2c-read request: bus:0x%02x addr:0x%02x reg:0x%0*x (+%lu bytes)\n",
                (unsigned int)bus, (unsigned int)addr, reglen, (unsigned int)reg, size);
    if ((st = ratp_barebox_link_i2c_read (ratp, timeout, bus, addr, reg, flags, size, &out, &out_size)) != RATP_STATUS_OK) {
        fprintf (stderr, "error: couldn't i2c-read: %s\n", ratp_status_str (st));
        ret = -1;
        goto out_close;
    }

    out_hex = strhex (out, out_size, ":");
    if (!out_hex) {
        fprintf (stderr, "error: couldn't hex print returned contents\n");
        ret = -2;
        goto out_close;
    }
    printf ("%s\n", out_hex);
    ret = 0;

out_close:

    if ((st = ratp_link_close_sync (ratp, 1000)) != RATP_STATUS_OK)
        fprintf (stderr, "warning: couldn't close link: %s\n", ratp_status_str (st));

out:
    free (out);
    free (out_hex);
    free (aux0);

    return ret;
}

static int
run_i2c_write (ratp_link_t  *ratp,
               const char   *action_args,
               unsigned int  timeout,
               bool          quiet)
{
    ratp_status_t  st;
    uint8_t       *data = NULL;
    size_t         data_size = 0;
    int            ret = -1;
    char          *aux0, *aux1, *aux2, *aux3;
    unsigned long  bus;
    unsigned long  addr;
    unsigned long  reg;
    uint16_t       written;
    int            reglen;
    ratp_barebox_link_i2c_flag_t flags = RATP_BAREBOX_LINK_I2C_FLAG_NONE;

    aux0 = strdup (action_args);
    if (!aux0)
        goto out;

    aux1 = strchr (aux0, ',');
    if (!aux1) {
        fprintf (stderr, "error: only one field given in --i2c-write arguments\n");
        goto out;
    }
    *aux1 = '\0';
    aux1++;

    aux2 = strchr (aux1, ',');
    if (!aux2) {
        fprintf (stderr, "error: only two fields given in --i2c-write arguments\n");
        goto out;
    }
    *aux2 = '\0';
    aux2++;

    aux3 = strchr (aux2, ',');
    if (!aux3) {
        fprintf (stderr, "error: only three fields given in --i2c-write arguments\n");
        goto out;
    }
    *aux3 = '\0';
    aux3++;

    bus = strtoul (aux0, NULL, 16);
    if (bus > 0xFF) {
        fprintf (stderr, "error: invalid bus number\n");
        goto out;
    }

    addr = strtoul (aux1, NULL, 16);
    if (addr > 0x7F) {
        fprintf (stderr, "error: invalid address\n");
        goto out;
    }

    if (aux2[0] == '\0') {
        reg = 0;
        flags |= RATP_BAREBOX_LINK_I2C_FLAG_MASTER_MODE;
    } else {
        if (strncmp (aux2, "0x", 2) == 0)
            aux2 += 2;
        reglen = strlen (aux2);
        if (reglen != 2 && reglen != 4) {
            fprintf (stderr, "error: invalid register: must be given either as 1 byte (0xAB) or 2 bytes (0xABCD)\n");
            goto out;
        }
        reg = strtoul (aux2, NULL, 16);
        assert (reglen <= 0xFFFF);
        if (reglen == 4)
            flags |= RATP_BAREBOX_LINK_I2C_FLAG_WIDE_ADDRESS;
    }

    data = hexstr (aux3, ":", &data_size);
    if (!data) {
        fprintf (stderr, "error: couldn't process input data\n");
        goto out;
    }

    if (data_size > 0xFFFF) {
        fprintf (stderr, "error: too much data\n");
        goto out;
    }

    if ((st = ratp_link_active_open_sync (ratp, 5000)) != RATP_STATUS_OK) {
        fprintf (stderr, "error: couldn't actively open link: %s\n", ratp_status_str (st));
        goto out;
    }

    if (!quiet)
        printf ("Sending i2c-write request: bus:0x%02x addr:0x%02x reg:0x%0*x (+%zu bytes)\n",
                (unsigned int)bus, (unsigned int)addr, reglen, (unsigned int)reg, data_size);
    if ((st = ratp_barebox_link_i2c_write (ratp, timeout, bus, addr, reg, flags, data, (uint16_t) data_size, &written)) != RATP_STATUS_OK) {
        fprintf (stderr, "error: couldn't i2c-write: %s\n", ratp_status_str (st));
        ret = -1;
        goto out_close;
    }

    printf ("%hu/%zu bytes written\n", written, data_size);
    ret = 0;

out_close:

    if ((st = ratp_link_close_sync (ratp, 1000)) != RATP_STATUS_OK)
        fprintf (stderr, "warning: couldn't close link: %s\n", ratp_status_str (st));

out:
    free (data);
    free (aux0);

    return ret;
}

static int
run_reset (ratp_link_t *ratp,
           bool         force,
           bool         quiet)
{
    ratp_status_t st;

    if ((st = ratp_link_active_open_sync (ratp, 5000)) != RATP_STATUS_OK) {
        fprintf (stderr, "error: couldn't actively open link: %s\n", ratp_status_str (st));
        return -1;
    }

    if ((st = ratp_barebox_link_reset (ratp, force)) != RATP_STATUS_OK) {
        fprintf (stderr, "error: couldn't reset: %s\n", ratp_status_str (st));
        return -1;
    }

    if ((st = ratp_link_close_sync (ratp, 1000)) != RATP_STATUS_OK)
        fprintf (stderr, "warning: couldn't close link: %s\n", ratp_status_str (st));

    return 0;
}

/******************************************************************************/

static void
print_help (void)
{
    printf ("\n"
            "Usage: " PROGRAM_NAME " <option>\n"
            "\n"
            "TTY link selection:\n"
            "  -t, --tty=[PATH]                            TTY device file path\n"
            "  -b, --tty-baudrate=[BAUDRATE]               Serial port baudrate\n"
            "\n"
            "FIFO link selection:\n"
            "  -i, --fifo-in=[PATH]                        FIFO input path.\n"
            "  -o, --fifo-out=[PATH]                       FIFO output path.\n"
            "\n"
            "Actions:\n"
            "  -p, --ping                                  PING barebox.\n"
            "  -c, --command=[COMMAND]                     Run a command in barebox.\n"
            "  -g, --getenv=[ENV]                          Read the value of an environment variable.\n"
            "  -m, --md=[PATH,0xADDR,SIZE]                 Memory dump SIZE bytes from file PATH at ADDR .\n"
            "  -w, --mw=[PATH,0xADDR,DATA]                 Memory write DATA to file PATH at ADDR.\n"
            "  -M, --i2c-read=[0xBUS,0xADDR,(0xREG),SIZE]  i2c read SIZE bytes from device at BUS/ADDR.\n"
            "  -W, --i2c-write=[0xBUS,0xADDR,(0xREG),DATA] i2c write DATA to device at BUS/ADDR.\n"
            "  -r, --reset                                 Request reset.\n"
            "  -R, --force-reset                           Request forced reset.\n"
            "\n"
            "Common options:\n"
            "  -T, --timeout=[TIMEOUT]                     Command timeout.\n"
            "  -q, --quiet                                 Display only command results.\n"
            "  -d, --debug                                 Enable verbose logging.\n"
            "  -h, --help                                  Show help.\n"
            "  -v, --version                               Show version.\n"
            "\n"
            "Notes:\n"
            " * [TIMEOUT] is given in milliseconds.\n"
            " * [BAUDRATE] may be any of:\n"
            "     9600, 19200, 38400, 57600, 115200 (default), 230400, 460800,\n"
            "     500000, 576000, 921600, 1000000, 1152000, 1500000, 2000000,\n"
            "     2500000, 3000000, 3500000 or 4000000.\n"
            " * [BUS] is an i2c bus number, given in hexadecimal format.\n"
            " * [ADDR] is an address, given in hexadecimal format.\n"
            "     For i2c read/write operations, if [ADDR] is given with 2 bytes (e.g. 0xABCD),\n"
            "     wide access is enabled implicitly.\n"
            " * [REG] is an i2c register number, in hexadecimal format.\n"
            "     If none given (empty), master send/receive mode is assumed.\n"
            " * [SIZE] is given in decimal format.\n"
            " * [DATA] is given in hex with 2 digits per byte and ':' as separator,\n"
            "     e.g.: '00:11:22:33'.\n"
            " * The MDL is 255 by default as that is what barebox expects.\n"
            "\n");
}

static void
print_version (void)
{
    printf ("\n"
            PROGRAM_NAME " " PROGRAM_VERSION "\n"
            "  running with libratp %u.%u.%u and libratp-barebox %u.%u.%u\n"
            "\n"
            "Copyright (2017-2018) Zodiac Inflight Innovations\n"
            "Copyright (2017-2018) Aleksander Morgado\n"
            "\n",
            ratp_get_major_version (), ratp_get_minor_version (), ratp_get_micro_version (),
            ratp_barebox_get_major_version (), ratp_barebox_get_minor_version (), ratp_barebox_get_micro_version ());
}

int main (int argc, char **argv)
{
    int            idx, iarg = 0;
    unsigned int   timeout = DEFAULT_TIMEOUT_MS;
    char          *tty_path = NULL;
    speed_t        tty_baudrate = B0;
    char          *fifo_in_path = NULL;
    char          *fifo_out_path = NULL;
    bool           action_ping = false;
    char          *action_command = NULL;
    char          *action_getenv = NULL;
    char          *action_md = NULL;
    char          *action_mw = NULL;
    char          *action_i2c_read = NULL;
    char          *action_i2c_write = NULL;
    bool           action_reset = NULL;
    bool           action_force_reset = NULL;
    bool           debug = false;
    bool           quiet = false;
    unsigned int   n_actions;
    int            action_ret;
    ratp_link_t   *ratp;
    ratp_status_t  st;

    const struct option longopts[] = {
        { "fifo-in",      required_argument, 0, 'i' },
        { "fifo-out",     required_argument, 0, 'o' },
        { "tty",          required_argument, 0, 't' },
        { "tty-baudrate", required_argument, 0, 'b' },
        { "ping",         no_argument,       0, 'p' },
        { "command",      required_argument, 0, 'c' },
        { "getenv",       required_argument, 0, 'g' },
        { "md",           required_argument, 0, 'm' },
        { "mw",           required_argument, 0, 'w' },
        { "i2c-read",     required_argument, 0, 'M' },
        { "i2c-write",    required_argument, 0, 'W' },
        { "reset",        no_argument,       0, 'r' },
        { "force-reset",  no_argument,       0, 'R' },
        { "timeout",      required_argument, 0, 'T' },
        { "quiet",        no_argument,       0, 'q' },
        { "debug",        no_argument,       0, 'd' },
        { "version",      no_argument,       0, 'v' },
        { "help",         no_argument,       0, 'h' },
        { 0,              0,                 0, 0   },
    };

    /* turn off getopt error message */
    opterr = 1;
    while (iarg != -1) {
        iarg = getopt_long (argc, argv, "i:o:t:b:pc:g:m:w:M:W:rRT:qdvh", longopts, &idx);
        switch (iarg) {
        case 'i':
            if (fifo_in_path)
                fprintf (stderr, "warning: -i,--fifo-in given multiple times\n");
            else
                fifo_in_path = strdup (optarg);
            break;
        case 'o':
            if (fifo_out_path)
                fprintf (stderr, "warning: -o,--fifo-out given multiple times\n");
            else
                fifo_out_path = strdup (optarg);
            break;
        case 't':
            if (tty_path)
                fprintf (stderr, "warning: -t,--tty given multiple times\n");
            else
                tty_path = strdup (optarg);
            break;
        case 'b':
            if (tty_baudrate != B0)
                fprintf (stderr, "warning: -b,--tty-baudrate given multiple times\n");
            else {
                unsigned int aux;

                aux = strtoul (optarg, NULL, 10);
                tty_baudrate = baudrate_from_num (aux);
                if (tty_baudrate == B0) {
                    fprintf (stderr, "error: invalid [BAUDRATE] given: %s\n", optarg);
                    return -1;
                }
            }
            break;
        case 'p':
            action_ping = true;
            break;
        case 'c':
            if (action_command)
                fprintf (stderr, "warning: -c,--command given multiple times\n");
            else
                action_command = strdup (optarg);
            break;
        case 'g':
            if (action_getenv)
                fprintf (stderr, "warning: -g,--getenv given multiple times\n");
            else
                action_getenv = strdup (optarg);
            break;
        case 'm':
            if (action_md)
                fprintf (stderr, "warning: -m,--md given multiple times\n");
            else
                action_md = strdup (optarg);
            break;
        case 'w':
            if (action_mw)
                fprintf (stderr, "warning: -w,--mw given multiple times\n");
            else
                action_mw = strdup (optarg);
            break;
        case 'M':
            if (action_i2c_read)
                fprintf (stderr, "warning: -M,--i2c-read given multiple times\n");
            else
                action_i2c_read = strdup (optarg);
            break;
        case 'W':
            if (action_i2c_write)
                fprintf (stderr, "warning: -W,--i2c-write given multiple times\n");
            else
                action_i2c_write = strdup (optarg);
            break;
        case 'r':
            action_reset = true;
            break;
        case 'R':
            action_force_reset = true;
            break;
        case 'T':
            timeout = strtoul (optarg, NULL, 10);
            break;
        case 'q':
            quiet = true;
            break;
        case 'd':
            debug = true;
            break;
        case 'h':
            print_help ();
            return 0;
        case 'v':
            print_version ();
            return 0;
        }
    }

    /* Validate actions */
    n_actions = (action_ping +
                 !!action_command +
                 !!action_getenv +
                 !!action_md +
                 !!action_mw +
                 !!action_i2c_read +
                 !!action_i2c_write +
                 action_reset +
                 action_force_reset);
    if (n_actions > 1) {
        fprintf (stderr, "error: too many actions requested\n");
        return -1;
    }
    if (n_actions == 0) {
        fprintf (stderr, "error: no actions requested\n");
        return -1;
    }

    /* Initialize RATP library */
    if ((st = ratp_init ()) != RATP_STATUS_OK) {
        fprintf (stderr, "error: couldn't initialize RATP library: %s\n", ratp_status_str (st));
        return -1;
    }

    /* Verbose library logging */
    if (debug) {
        main_tid = (unsigned long) pthread_self ();
        ratp_log_set_level (RATP_LOG_LEVEL_DEBUG);
        ratp_log_set_handler (ratp_log_handler);
        ratp_barebox_log_set_level (RATP_BAREBOX_LOG_LEVEL_DEBUG);
        ratp_barebox_log_set_handler (ratp_barebox_log_handler);
    }

    /* Setup signals */
    signal (SIGHUP, sig_handler);
    signal (SIGINT, sig_handler);

    /* Validate input paths and create RATP link */
    if (fifo_in_path || fifo_out_path) {
        if (!fifo_in_path || !fifo_out_path) {
            fprintf (stderr, "error: FIFO based RATP link requires both input and output paths\n");
            return -2;
        }
        ratp = ratp_link_new_fifo (fifo_in_path, fifo_out_path, 255);
        if (!ratp) {
            fprintf (stderr, "error: couldn't create FIFO based RATP link\n");
            return -2;
        }
    } else if (tty_path) {
        ratp = ratp_link_new_tty (tty_path, tty_baudrate != B0 ? tty_baudrate : B115200, 255);
        if (!ratp) {
            fprintf (stderr, "error: couldn't create TTY based RATP link\n");
            return -2;
        }
    } else {
        fprintf (stderr, "error: no link selected\n");
        return -2;
    }

    /* Initialize RATP link */
    if ((st = ratp_link_initialize (ratp)) != RATP_STATUS_OK) {
        fprintf (stderr, "error: couldn't initialize RATP link: %s\n", ratp_status_str (st));
        return -3;
    }

    if (action_ping)
        action_ret = run_ping (ratp, timeout, quiet);
    else if (action_command)
        action_ret = run_command (ratp, action_command, timeout, quiet);
    else if (action_getenv)
        action_ret = run_getenv (ratp, action_getenv, timeout, quiet);
    else if (action_md)
        action_ret = run_md (ratp, action_md, timeout, quiet);
    else if (action_mw)
        action_ret = run_mw (ratp, action_mw, timeout, quiet);
    else if (action_i2c_read)
        action_ret = run_i2c_read (ratp, action_i2c_read, timeout, quiet);
    else if (action_i2c_write)
        action_ret = run_i2c_write (ratp, action_i2c_write, timeout, quiet);
    else if (action_reset)
        action_ret = run_reset (ratp, false, quiet);
    else if (action_force_reset)
        action_ret = run_reset (ratp, true, quiet);
    else
        assert (0);

    free (action_i2c_write);
    free (action_i2c_read);
    free (action_mw);
    free (action_md);
    free (action_getenv);
    free (action_command);

    ratp_link_shutdown (ratp);
    ratp_link_free (ratp);
    return action_ret;
}
