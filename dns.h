/*
 * Copyright (c) 2020 The University of Queensland
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#if !defined(_DNS_H)
#define	_DNS_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <stdint.h>

struct dns_buf;

enum dns_flags {
	DNS_QR = 0x8000,
	DNS_OPCODE = 0x7800,
	DNS_AA = 0x0400,
	DNS_TC = 0x0200,
	DNS_RD = 0x0100,
	DNS_RA = 0x0080,
	DNS_Z = 0x0040,
	DNS_AD = 0x0020,
	DNS_CD = 0x0010,
	DNS_RCODE = 0x00F
};

enum dns_parser_rc {
	DNS_R_OK = 0,
	DNS_R_NOMEM = 1,
	DNS_R_SHORT = 2,
	DNS_R_ERROR = 3,
	DNS_R_PTRLIMIT = 4
};

enum dns_rcode {
	DNS_NOERROR = 0,
	DNS_FORMERR = 1,
	DNS_SERVFAIL = 2,
	DNS_NXDOMAIN = 3,
	DNS_NOTIMP = 4,
	DNS_REFUSED = 5,
	DNS_YXDOMAIN = 6,
	DNS_XRRSET = 7,
	DNS_NOTAUTH = 9,
	DNS_NOTZONE = 10
};

enum dns_opcode {
	DNS_QUERY = 0,
	DNS_IQUERY = 1,
	DNS_STATUS = 2,
	DNS_NOTIFY = 4,
	DNS_UPDATE = 5
};

enum dns_type {
	DNS_T_A = 0x01,
	DNS_T_NS = 0x02,
	DNS_T_CNAME = 0x05,
	DNS_T_SOA = 0x06,
	DNS_T_PTR = 0x0C,
	DNS_T_TXT = 0x10,
	DNS_T_AAAA = 0x1C
};

enum dns_class {
	DNS_C_IN = 0x01,
	DNS_C_CS = 0x02,
	DNS_C_CH = 0x03,
	DNS_C_HS = 0x04,
	DNS_C_ANY = 0xFF
};

struct dns_header {
	uint16_t 	dh_id;
	enum dns_flags 	dh_flags;
	enum dns_opcode	dh_opcode;
	enum dns_rcode	dh_rcode;
	uint16_t	dh_questions;
	uint16_t	dh_answers;
	uint16_t	dh_authorities;
	uint16_t	dh_additionals;
};

struct dns_question {
	const char *	dq_name;
	enum dns_type	dq_type;
	enum dns_class	dq_class;
};

struct dns_record {
	const char *	dr_name;
	enum dns_type	dr_type;
	enum dns_class	dr_class;
	uint32_t	dr_ttl;
	union {
		struct {
			const u_char *	_dr_buf;
			size_t		_dr_len;
		} _dr_raw_data;
		struct in_addr 		_dr_a_data;
		struct in6_addr		_dr_aaaa_data;
	}		dr_data;
};

struct dns_buf *dns_buf_from(const u_char *, size_t);
void dns_buf_free(struct dns_buf *);

enum dns_parser_rc dns_read_header(struct dns_buf *,
    const struct dns_header **);
enum dns_parser_rc dns_read_question(struct dns_buf *,
    const struct dns_question **);
enum dns_parser_rc dns_read_record(struct dns_buf *,
    const struct dns_record **);

#endif
