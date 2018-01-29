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

#define DEFAULT_TIMEOUT 5000

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

/******************************************************************************/

static void
print_help (void)
{
    printf ("\n"
            "Usage: " PROGRAM_NAME " <option>\n"
            "\n"
            "TTY link selection:\n"
            "  -t, --tty=[PATH]                TTY device file path\n"
            "  -b, --tty-baudrate=[BAUDRATE]   Serial port baudrate\n"
            "\n"
            "FIFO link selection:\n"
            "  -i, --fifo-in=[PATH]            FIFO input path.\n"
            "  -o, --fifo-out=[PATH]           FIFO output path.\n"
            "\n"
            "Actions:\n"
            "  -p, --ping                      PING barebox.\n"
            "  -c, --command=[COMMAND]         Run a command in barebox.\n"
            "  -g, --getenv=[ENV]              Read the value of an environment variable.\n"
            "\n"
            "Common options:\n"
            "  -T, --timeout                   Command timeout.\n"
            "  -q, --quiet                     Display only command results.\n"
            "  -d, --debug                     Enable verbose logging.\n"
            "  -h, --help                      Show help.\n"
            "  -v, --version                   Show version.\n"
            "\n"
            "Notes:\n"
            " * [BAUDRATE] may be any of:\n"
            "     9600, 19200, 38400, 57600, 115200 (default), 230400, 460800,\n"
            "     500000, 576000, 921600, 1000000, 1152000, 1500000, 2000000,\n"
            "     2500000, 3000000, 3500000 or 4000000.\n"
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
            "Copyright (2017) Zodiac Inflight Innovations\n"
            "Copyright (2017) Aleksander Morgado\n"
            "\n",
            ratp_get_major_version (), ratp_get_minor_version (), ratp_get_micro_version (),
            ratp_barebox_get_major_version (), ratp_barebox_get_minor_version (), ratp_barebox_get_micro_version ());
}

int main (int argc, char **argv)
{
    int            idx, iarg = 0;
    unsigned int   timeout = DEFAULT_TIMEOUT;
    char          *tty_path = NULL;
    speed_t        tty_baudrate = B0;
    char          *fifo_in_path = NULL;
    char          *fifo_out_path = NULL;
    bool           action_ping = false;
    char          *action_command = NULL;
    char          *action_getenv = NULL;
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
        iarg = getopt_long (argc, argv, "i:o:t:b:pc:g:T:qdvh", longopts, &idx);
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
    n_actions = (action_ping + !!action_command + !!action_getenv);
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
    else
        assert (0);

    free (action_getenv);
    free (action_command);

    ratp_link_shutdown (ratp);
    ratp_link_free (ratp);
    return action_ret;
}
