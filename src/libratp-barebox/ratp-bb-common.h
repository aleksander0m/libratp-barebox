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
#define BB_RATP_TYPE_MD                 10
#define BB_RATP_TYPE_MD_RETURN          11
#define BB_RATP_TYPE_MW                 12
#define BB_RATP_TYPE_MW_RETURN          13
#define BB_RATP_TYPE_RESET              14

struct ratp_bb {
  uint16_t type;
  uint16_t flags;
  uint8_t data[];
} __attribute__((packed));

struct ratp_bb_command_return {
  uint32_t errno_v;
} __attribute__((packed));

/* NOTE:
 *  - Fixed-size fields (e.g. integers) are given just after the header.
 *  - Variable-length fields are stored inside the buffer[] and their position
 *    within the buffer[] and their size are given as fixed-sized fields after
 *    the header.
 *  The message may be extended at any time keeping backwards compatibility,
 *  as the position of the buffer[] is given by the buffer_offset field. i.e.
 *  increasing the buffer_offset field we can extend the fixed-sized section
 *  to add more fields.
 */

struct ratp_bb_md_request {
	struct ratp_bb header;
	uint16_t buffer_offset;
	uint16_t addr;
	uint16_t size;
	uint16_t path_size;
	uint16_t path_offset;
	uint8_t  buffer[];
} __attribute__((packed));

struct ratp_bb_md_response {
	struct ratp_bb header;
	uint16_t buffer_offset;
	uint32_t errno_v;
	uint16_t data_size;
	uint16_t data_offset;
	uint8_t  buffer[];
} __attribute__((packed));

struct ratp_bb_mw_request {
	struct ratp_bb header;
	uint16_t buffer_offset;
	uint16_t addr;
	uint16_t path_size;
	uint16_t path_offset;
	uint16_t data_size;
	uint16_t data_offset;
	uint8_t  buffer[];
} __attribute__((packed));


struct ratp_bb_mw_response {
	struct ratp_bb header;
	uint16_t buffer_offset;
	uint32_t errno_v;
	uint32_t written;
	uint8_t  buffer[];
} __attribute__((packed));

#endif /* __RATP_BB_COMMON_H */
