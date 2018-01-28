#ifndef __RATP_BB_COMMON_H
#define __RATP_BB_COMMON_H

#include <stdint.h>


#define BB_RATP_TYPE_CONSOLE            1
#define BB_RATP_TYPE_PING               2
#define BB_RATP_TYPE_GETENV             3
#define BB_RATP_TYPE_FS                 4

#define BB_RATP_FLAG_NONE               0
#define BB_RATP_FLAG_RESPONSE           (1 << 0) /* Packet is a response */
#define BB_RATP_FLAG_INDICATION         (1 << 1) /* Packet is an indication */

struct ratp_bb {
  uint16_t type;
  uint16_t flags;
  uint8_t data[];
} __attribute__((packed));

struct ratp_bb_command_return {
  uint32_t errno_v;
} __attribute__((packed));

#endif /* __RATP_BB_COMMON_H */
