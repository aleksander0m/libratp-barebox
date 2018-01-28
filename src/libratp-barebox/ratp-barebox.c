/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * Copyright (C) 2015 Zodiac Inflight Innovations
 * All rights reserved.
 *
 * Author: Aleksander Morgado <aleksander@aleksander.es>
 */

#define _GNU_SOURCE
#define _DEFAULT_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <malloc.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>

#include "ratp-barebox.h"
#include "ratp-bb-common.h"

/******************************************************************************/

#define ratp_barebox_error(...)   ratp_barebox_log (RATP_BAREBOX_LOG_LEVEL_ERROR,   (unsigned long) pthread_self (), ## __VA_ARGS__ )
#define ratp_barebox_warning(...) ratp_barebox_log (RATP_BAREBOX_LOG_LEVEL_WARNING, (unsigned long) pthread_self (), ## __VA_ARGS__ )
#define ratp_barebox_info(...)    ratp_barebox_log (RATP_BAREBOX_LOG_LEVEL_INFO,    (unsigned long) pthread_self (), ## __VA_ARGS__ )
#define ratp_barebox_debug(...)   ratp_barebox_log (RATP_BAREBOX_LOG_LEVEL_DEBUG,   (unsigned long) pthread_self (), ## __VA_ARGS__ )

static void ratp_barebox_log (ratp_barebox_log_level_t  level,
                              unsigned long             tid,
                              const char               *fmt,
                              ...)  __attribute__((__format__ (__printf__, 3, 4)));

/******************************************************************************/
/* Common operation context */

struct operation_context_s {
    uint16_t         expected_rsp_type;
    bool             propagate_rsp;
    uint8_t         *rsp;
    size_t           rsp_size;
    bool             propagate_stdout;
    char            *stdout;
    size_t           stdout_size;
    pthread_mutex_t  sync_lock;
    pthread_cond_t   sync_cond;
};

static void
operation_receive_ready (ratp_link_t   *self,
                         const uint8_t *buffer,
                         size_t         buffer_size,
                         void          *user_data)
{
    struct operation_context_s *ctx;
    struct ratp_bb             *rsp_msg;
    uint16_t                    msg_type;
    uint16_t                    msg_flags;

    ctx = (struct operation_context_s *) user_data;
    rsp_msg = (struct ratp_bb *) buffer;

    if (buffer_size < sizeof (struct ratp_bb)) {
        ratp_barebox_warning ("received buffer is not a RATP Barebox message (too short): %zu < %zu",
                              buffer_size, sizeof (struct ratp_bb));
        return;
    }

    msg_type = be16toh (rsp_msg->type);
    msg_flags = be16toh (rsp_msg->flags);

    if (msg_flags & BB_RATP_FLAG_INDICATION) {
        size_t  console_message_size;
        size_t  new_stdout_size;
        char   *aux;

        /* Only console indications supported for now */
        if (msg_type != BB_RATP_TYPE_CONSOLE) {
            ratp_barebox_debug ("ignoring unsupported indication (%hu)", msg_type);
            return;
        }

        console_message_size = buffer_size - sizeof (struct ratp_bb);
        if (!console_message_size)
            return;

        ratp_barebox_debug ("console message received: '%.*s'", (int) console_message_size, rsp_msg->data);

        if (!ctx->propagate_stdout)
            return;

        new_stdout_size = ctx->stdout_size + console_message_size;
        aux = realloc (ctx->stdout, new_stdout_size + 1);
        if (!aux) {
            ratp_barebox_warning ("couldn't reallocate stdout buffer (%zu bytes)", new_stdout_size + 1);
            return;
        }
        ctx->stdout = aux;
        memcpy (&ctx->stdout[ctx->stdout_size], rsp_msg->data, console_message_size);
        ctx->stdout[new_stdout_size] = '\0';
        ctx->stdout_size = new_stdout_size;
        return;
    }

    /* We don't support receiving requests here */
    if (!(msg_flags & BB_RATP_FLAG_RESPONSE)) {
        ratp_barebox_debug ("ignoring unsupported request (%hu)", msg_type);
        return;
    }

    if (msg_type != ctx->expected_rsp_type) {
        ratp_barebox_debug ("ignoring unexpected response (%hu != %hu)",
                            msg_type, ctx->expected_rsp_type);
        return;
    }

    if (ctx->propagate_rsp) {
        ctx->rsp = malloc (buffer_size);
        if (!ctx->rsp) {
            ratp_barebox_warning ("couldn't allocate response buffer (%zu bytes)", buffer_size);
            return;
        }
        memcpy (ctx->rsp, buffer, buffer_size);
        ctx->rsp_size = buffer_size;
    }

    pthread_mutex_lock   (&ctx->sync_lock);
    pthread_cond_signal  (&ctx->sync_cond);
    pthread_mutex_unlock (&ctx->sync_lock);
}

static ratp_status_t
operation (ratp_link_t    *ratp,
           unsigned long   timeout_ms,
           const uint8_t  *msg,
           size_t          msg_size,
           char          **stdout,
           uint8_t       **rsp,
           size_t         *rsp_size)
{
    ratp_status_t              st;
    struct operation_context_s ctx = { 0 };
    struct timespec            absolute_timeout;

    pthread_mutex_init (&ctx.sync_lock, NULL);
    pthread_cond_init  (&ctx.sync_cond, NULL);
    ctx.expected_rsp_type = be16toh (((struct ratp_bb *)msg)->type);
    ctx.propagate_rsp = (rsp && rsp_size);
    ctx.propagate_stdout = !!stdout;

    clock_gettime (CLOCK_REALTIME, &absolute_timeout);
    absolute_timeout.tv_sec  += (timeout_ms / 1000);
    absolute_timeout.tv_nsec += ((timeout_ms % 1000) * 1E6);
    if (absolute_timeout.tv_nsec >= 1E9) {
        absolute_timeout.tv_nsec -= 1E9;
        absolute_timeout.tv_sec++;
    }

    ratp_link_set_receive_callback (ratp, (ratp_link_receive_ready_func) operation_receive_ready, &ctx);

    if ((st = ratp_link_send (ratp, 0, msg, msg_size, NULL, NULL)) != RATP_STATUS_OK)
        goto out;

    pthread_mutex_lock (&ctx.sync_lock);
    if (pthread_cond_timedwait (&ctx.sync_cond, &ctx.sync_lock, &absolute_timeout) != 0) {
        st = RATP_STATUS_TIMEOUT;
        goto out;
    }

    st = RATP_STATUS_OK;

    if (ctx.propagate_rsp) {
        *rsp      = ctx.rsp;
        *rsp_size = ctx.rsp_size;
    } else {
        assert (!ctx.rsp);
        assert (!ctx.rsp_size);
    }

    if (ctx.propagate_stdout)
        *stdout = ctx.stdout;
    else
        assert (!ctx.stdout);

out:
    ratp_link_set_receive_callback (ratp, NULL, NULL);
    pthread_mutex_destroy (&ctx.sync_lock);
    pthread_cond_destroy  (&ctx.sync_cond);
    return st;
}

/******************************************************************************/
/* Ping */

ratp_status_t
ratp_barebox_link_ping (ratp_link_t   *ratp,
                        unsigned long  timeout_ms)
{
    struct ratp_bb msg;

    msg.type  = htobe16 (BB_RATP_TYPE_PING);
    msg.flags = 0;

    return operation (ratp,
                      timeout_ms,
                      (const uint8_t *) &msg, sizeof (msg),
                      NULL, NULL, NULL);
}

/******************************************************************************/
/* Command */

ratp_status_t
ratp_barebox_link_command (ratp_link_t    *ratp,
                           unsigned long   timeout_ms,
                           const char     *command,
                           uint32_t       *out_errno_result,
                           char          **out_stdout_result)
{
    struct ratp_bb *msg;
    size_t          command_len;
    size_t          msg_size;
    uint8_t        *response = NULL;
    size_t          response_size = 0;
    uint8_t        *stdout = NULL;
    ratp_status_t   st;

    command_len = strlen (command);
    msg_size = sizeof (struct ratp_bb) + command_len;

    msg = (struct ratp_bb *) calloc (msg_size + 1, 1);
    if (!msg)
        return RATP_STATUS_ERROR_NO_MEMORY;

    msg->type  = htobe16 (BB_RATP_TYPE_CONSOLE);
    msg->flags = 0;
    memcpy (msg->data, command, command_len);

    if ((st = operation (ratp,
                         timeout_ms,
                         (const uint8_t *) msg, msg_size,
                         out_stdout_result,
                         &response, &response_size)) != RATP_STATUS_OK)
        goto out;

    if (response_size != (sizeof (struct ratp_bb) + sizeof (uint32_t))) {
        ratp_barebox_warning ("unexpected response size (%zu != %zu)",
                              response_size, (sizeof (struct ratp_bb) + sizeof (uint32_t)));
        st = RATP_STATUS_INVALID_DATA;
        goto out;
    }

    st = RATP_STATUS_OK;

    if (out_errno_result) {
        uint32_t value;

        memcpy (&value, ((struct ratp_bb *)(response))->data, sizeof (value));
        *out_errno_result = be32toh (value);
    }

out:
    free (msg);
    free (response);
    return st;
}

/******************************************************************************/
/* Get env */

ratp_status_t
ratp_barebox_link_getenv (ratp_link_t    *ratp,
                          unsigned long   timeout_ms,
                          const char     *env_name,
                          char          **env_value)
{
    struct ratp_bb *msg;
    size_t          env_name_len;
    size_t          msg_size;
    ratp_status_t   st;
    uint8_t        *response;
    size_t          response_size;;

    env_name_len = strlen (env_name);
    msg_size = sizeof (struct ratp_bb) + env_name_len;

    msg = (struct ratp_bb *) calloc (msg_size + 1, 1);
    if (!msg)
        return RATP_STATUS_ERROR_NO_MEMORY;

    msg->type  = htobe16 (BB_RATP_TYPE_GETENV);
    msg->flags = 0;
    memcpy (msg->data, env_name, env_name_len);

    if ((st = operation (ratp,
                         timeout_ms,
                         (const uint8_t *) msg, msg_size,
                         NULL,
                         &response, &response_size)) != RATP_STATUS_OK)
        goto out;

    if (response_size < sizeof (struct ratp_bb)) {
        ratp_barebox_warning ("unexpected response size (%zu < %zu)",
                              response_size, (sizeof (struct ratp_bb)));
        st = RATP_STATUS_INVALID_DATA;
        goto out;
    }

    st = RATP_STATUS_OK;

    if (env_value) {
        *env_value = strndup ((char *) ((struct ratp_bb *)response)->data, response_size - sizeof (struct ratp_bb));
        if (!*env_value)
            st = RATP_STATUS_ERROR_NO_MEMORY;
    }

out:
    free (response);
    free (msg);
    return st;
}

/******************************************************************************/
/* Reset */

struct ratp_bb_reset {
	struct ratp_bb header;
	uint8_t        force;
} __attribute__((packed));

ratp_status_t
ratp_barebox_link_reset (ratp_link_t *ratp,
                         bool         force)
{

    struct ratp_bb_reset *msg;
    size_t                msg_size;
    ratp_status_t         st;

    msg_size = sizeof (struct ratp_bb_reset);
    msg = (struct ratp_bb_reset *) calloc (msg_size, 1);
    if (!msg)
        return RATP_STATUS_ERROR_NO_MEMORY;

    msg->header.type  = htobe16 (BB_RATP_TYPE_RESET);
    msg->header.flags = 0;
    msg->force = (uint8_t) force;

    st = ratp_link_send (ratp, 0, (const uint8_t *) msg, msg_size, NULL, NULL);

    free (msg);
    return st;
}

/******************************************************************************/
/* Library logging */

static ratp_barebox_log_handler_t default_handler = NULL;
static ratp_barebox_log_level_t   default_level   = RATP_BAREBOX_LOG_LEVEL_ERROR;

static const char *level_str[] = {
    "error",
    "warn ",
    "info ",
    "debug"
};

const char *
ratp_barebox_log_level_str (ratp_barebox_log_level_t level)
{
    return level_str [level];
}

void
ratp_barebox_log_set_level (ratp_barebox_log_level_t level)
{
    default_level = level;
}

ratp_barebox_log_level_t
ratp_barebox_log_get_level (void)
{
    return default_level;
}

void
ratp_barebox_log_set_handler (ratp_barebox_log_handler_t handler)
{
    default_handler = handler;
}

static void
ratp_barebox_log (ratp_barebox_log_level_t  level,
                  unsigned long             tid,
                  const char               *fmt,
                  ...)
{
    char *message;
    va_list args;

    /* Only keep on if the log level allows us */
    if (level > ratp_barebox_log_get_level () || !default_handler)
      return;

    va_start (args, fmt);
    if (vasprintf (&message, fmt, args) == -1)
        return;
    va_end (args);

    default_handler (level, tid, message);
    free (message);
}

/******************************************************************************/
/* Library version info */

unsigned int
ratp_barebox_get_major_version (void)
{
    return RATP_BAREBOX_MAJOR_VERSION;
}

unsigned int
ratp_barebox_get_minor_version (void)
{
    return RATP_BAREBOX_MINOR_VERSION;
}

unsigned int
ratp_barebox_get_micro_version (void)
{
    return RATP_BAREBOX_MICRO_VERSION;
}
