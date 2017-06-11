#ifndef __RATP_BB_COMMON_H
#define __RATP_BB_COMMON_H

#include <stdint.h>

#define BB_RATP_TYPE_COMMAND            1
#define BB_RATP_TYPE_COMMAND_RETURN     2
#define BB_RATP_TYPE_CONSOLEMSG         3
#define BB_RATP_TYPE_PING               4
#define BB_RATP_TYPE_PONG               5
#define BB_RATP_TYPE_GETENV             6
#define BB_RATP_TYPE_GETENV_RETURN      7
#define BB_RATP_TYPE_FS                 8
#define BB_RATP_TYPE_FS_RETURN          9

struct ratp_bb {
  uint16_t type;
  uint16_t flags;
  uint8_t data[];
} __attribute__((packed));

struct ratp_bb_command_return {
  uint32_t errno_v;
} __attribute__((packed));

#endif /* __RATP_BB_COMMON_H */
