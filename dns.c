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

#include "dns.h"

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <pwd.h>
#include <paths.h>
#include <ctype.h>

#include <net/if.h>
#include <net/if_arp.h>
#include <netdb.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include <sys/queue.h>
#include <sys/tree.h>

struct question {
	TAILQ_ENTRY(question)	q_entry;
	char			q_nbuf[512];
	struct dns_question 	q;
};

struct record {
	TAILQ_ENTRY(record)	r_entry;
	char			r_nbuf[512];
	u_char			r_dbuf[512];
	struct dns_record	r;
};

TAILQ_HEAD(question_list, question);
TAILQ_HEAD(record_list, record);

struct dns_buf {
	const u_char *		db_buf;
	const u_char *		db_ptr;
	size_t 			db_len;
	size_t			db_rem;
	struct dns_header 	db_head;
	struct question_list 	db_qs;
	struct record_list	db_rs;
};

struct dns_buf *
dns_buf_from(const u_char *buf, size_t len)
{
	struct dns_buf *db;

	db = calloc(1, sizeof(*db));
	if (db == NULL)
		return (NULL);
	db->db_buf = buf;
	db->db_ptr = buf;
	db->db_len = len;
	db->db_rem = len;
	TAILQ_INIT(&db->db_qs);
	TAILQ_INIT(&db->db_rs);
	return (db);
}

void
dns_buf_free(struct dns_buf *db)
{
	struct question *q, *nq;
	struct record *r, *nr;

	TAILQ_FOREACH_SAFE(q, &db->db_qs, q_entry, nq) {
		free(q);
	}
	TAILQ_FOREACH_SAFE(r, &db->db_rs, r_entry, nr) {
		free(r);
	}

	free(db);
}

static enum dns_parser_rc
dns_read_uint8(struct dns_buf *db, uint8_t *retp)
{
	if (db->db_rem < sizeof(*retp))
		return (DNS_R_SHORT);
	db->db_rem -= sizeof(*retp);
	*retp = *db->db_ptr++;
	return (DNS_R_OK);
}

static enum dns_parser_rc
dns_read_chars(struct dns_buf *db, char *buf, size_t len)
{
	size_t i;

	if (db->db_rem < len)
		return (DNS_R_SHORT);
	db->db_rem -= len;
	for (i = 0; i < len; i++) {
		int ch = *db->db_ptr++;
		if (!isprint(ch))
			return (DNS_R_ERROR);
		buf[i] = ch;
	}
	return (DNS_R_OK);
}

static enum dns_parser_rc
dns_read_uint16(struct dns_buf *db, uint16_t *retp)
{
	if (db->db_rem < sizeof(*retp))
		return (DNS_R_SHORT);
	db->db_rem -= sizeof(*retp);
	*retp = *db->db_ptr++ << 8;
	*retp |= *db->db_ptr++;
	return (DNS_R_OK);
}

static enum dns_parser_rc
dns_read_uint32(struct dns_buf *db, uint32_t *retp)
{
	if (db->db_rem < sizeof(*retp))
		return (DNS_R_SHORT);
	db->db_rem -= sizeof(*retp);
	*retp = *db->db_ptr++ << 24;
	*retp |= *db->db_ptr++ << 16;
	*retp |= *db->db_ptr++ << 8;
	*retp |= *db->db_ptr++;
	return (DNS_R_OK);
}

enum dns_parser_rc
dns_read_header(struct dns_buf *db, const struct dns_header **retp)
{
	struct dns_header *dh = &db->db_head;
	enum dns_parser_rc rc;
	uint16_t flags;

	if ((rc = dns_read_uint16(db, &dh->dh_id)))
		return (rc);
	if ((rc = dns_read_uint16(db, &flags)))
		return (rc);
	dh->dh_flags = flags & ~(DNS_OPCODE | DNS_RCODE);
	if (flags & DNS_QR)
		dh->dh_rcode = flags & DNS_RCODE;
	dh->dh_opcode = (flags & DNS_OPCODE) >> 11;
	if ((rc = dns_read_uint16(db, &dh->dh_questions)))
		return (rc);
	if ((rc = dns_read_uint16(db, &dh->dh_answers)))
		return (rc);
	if ((rc = dns_read_uint16(db, &dh->dh_authorities)))
		return (rc);
	if ((rc = dns_read_uint16(db, &dh->dh_additionals)))
		return (rc);

	*retp = dh;
	return (DNS_R_OK);
}

enum name_meta {
	DNS_NAME_MASK = 0xC0,
	DNS_NAME_STRING = 0x00,
	DNS_NAME_PTR = 0xC0
};

static enum dns_parser_rc
dns_read_name(struct dns_buf *db, char *buf, size_t buflen, u_int depth)
{
	char *optr = buf;
	const u_char *pptr;
	size_t prem;
	size_t rem = buflen - 1;
	uint8_t rlen, ptrl;
	uint16_t ptr;
	enum dns_parser_rc rc;

	if ((rc = dns_read_uint8(db, &rlen)))
		return (rc);
	while (rlen != 0 && rem > 0) {
		switch (rlen & DNS_NAME_MASK) {

		case DNS_NAME_STRING:
			if (rem < rlen + 1)
				return (DNS_R_NOMEM);
			if (optr != buf) {
				*optr++ = '.';
				--rem;
			}
			if ((rc = dns_read_chars(db, optr, rlen)))
				return (rc);
			optr += rlen;
			rem -= rlen;
			break;

		case DNS_NAME_PTR:
			if (depth == 0)
				return (DNS_R_PTRLIMIT);

			if ((rc = dns_read_uint8(db, &ptrl)))
				return (rc);
			ptr = ((rlen & ~DNS_NAME_MASK) << 8) | ptrl;

			if (ptr > (db->db_ptr - db->db_buf))
				return (DNS_R_ERROR);

			if (optr != buf) {
				*optr++ = '.';
				--rem;
			}
			if (rem < 2)
				return (DNS_R_NOMEM);

			pptr = db->db_ptr;
			prem = db->db_rem;

			db->db_ptr = db->db_buf + ptr;
			db->db_rem = db->db_len - ptr;
			rc = dns_read_name(db, optr, rem, depth - 1);
			db->db_ptr = pptr;
			db->db_rem = prem;
			return (rc);
		}
		if ((rc = dns_read_uint8(db, &rlen)))
			return (rc);
	}
	*optr++ = '\0';

	return (DNS_R_OK);
}

enum dns_parser_rc
dns_read_question(struct dns_buf *db, const struct dns_question **retp)
{
	struct question *q;
	struct dns_question *dq;
	enum dns_parser_rc rc;
	uint16_t tmp16;

	q = calloc(1, sizeof(*q));
	if (q == NULL)
		return (DNS_R_NOMEM);
	dq = &q->q;

	if ((rc = dns_read_name(db, q->q_nbuf, sizeof(q->q_nbuf), 3)))
		goto err;
	dq->dq_name = q->q_nbuf;
	if ((rc = dns_read_uint16(db, &tmp16)))
		goto err;
	dq->dq_type = tmp16;
	if ((rc = dns_read_uint16(db, &tmp16)))
		goto err;
	dq->dq_class = tmp16;

	TAILQ_INSERT_TAIL(&db->db_qs, q, q_entry);
	*retp = dq;
	return (DNS_R_OK);
err:
	free(q);
	return (rc);
}

enum dns_parser_rc
dns_read_record(struct dns_buf *db, const struct dns_record **retp)
{
	struct record *r;
	struct dns_record *dr;
	enum dns_parser_rc rc;
	uint16_t tmp16;

	r = calloc(1, sizeof(*r));
	if (r == NULL)
		return (DNS_R_NOMEM);
	dr = &r->r;

	if ((rc = dns_read_name(db, r->r_nbuf, sizeof(r->r_nbuf), 3)))
		goto err;
	dr->dr_name = r->r_nbuf;
	if ((rc = dns_read_uint16(db, &tmp16)))
		goto err;
	dr->dr_type = tmp16;
	if ((rc = dns_read_uint16(db, &tmp16)))
		goto err;
	dr->dr_class = tmp16;
	if ((rc = dns_read_uint32(db, &dr->dr_ttl)))
		goto err;

	if ((rc = dns_read_uint16(db, &tmp16)))
		goto err;
	if (db->db_rem < tmp16)
		return (DNS_R_SHORT);
	db->db_rem -= tmp16;

	switch (dr->dr_type) {
	case DNS_T_A:
		bcopy(db->db_ptr, &dr->dr_data._dr_a_data, tmp16);
		break;
	case DNS_T_AAAA:
		bcopy(db->db_ptr, &dr->dr_data._dr_aaaa_data, tmp16);
		break;
	default:
		dr->dr_data._dr_raw_data._dr_buf = db->db_ptr;
		dr->dr_data._dr_raw_data._dr_len = tmp16;
	}

	TAILQ_INSERT_TAIL(&db->db_rs, r, r_entry);
	db->db_ptr += tmp16;
	*retp = dr;
	return (DNS_R_OK);
err:
	free(r);
	return (rc);
}
