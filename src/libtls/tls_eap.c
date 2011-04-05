/*
 * Copyright (C) 2010 Martin Willi
 * Copyright (C) 2010 revosec AG
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "tls_eap.h"

#include "tls.h"

#include <debug.h>
#include <library.h>

/** Size limit for a single TLS message */
#define MAX_TLS_MESSAGE_LEN 65536

typedef struct private_tls_eap_t private_tls_eap_t;

/**
 * Private data of an tls_eap_t object.
 */
struct private_tls_eap_t {

	/**
	 * Public tls_eap_t interface.
	 */
	tls_eap_t public;

	/**
	 * Type of EAP method, EAP-TLS, EAP-TTLS, or EAP-TNC
	 */
	eap_type_t type;

	/**
	 * Current value of EAP identifier
	 */
	u_int8_t identifier;

	/**
	 * TLS stack
	 */
	tls_t *tls;

	/**
	 * Role
	 */
	bool is_server;

	/**
	 * First fragment of a multi-fragment record?
	 */
	bool first_fragment;

	/**
	 * Maximum size of an outgoing EAP-TLS fragment
	 */
	size_t frag_size;

	/**
	 * Number of EAP messages/fragments processed so far
	 */
	int processed;

	/**
	 * Maximum number of processed EAP messages/fragments 
	 */
	int max_msg_count;
};

/**
 * Flags of an EAP-TLS/TTLS/TNC message
 */
typedef enum {
	EAP_TLS_LENGTH = (1<<7),		/* shared with EAP-TTLS/TNC/PEAP */
	EAP_TLS_MORE_FRAGS = (1<<6),	/* shared with EAP-TTLS/TNC/PEAP */
	EAP_TLS_START = (1<<5),			/* shared with EAP-TTLS/TNC/PEAP */
	EAP_TTLS_VERSION = (0x07),		/* shared with EAP-TNC/PEAP      */
} eap_tls_flags_t;

#define EAP_TTLS_SUPPORTED_VERSION	0
#define EAP_TNC_SUPPORTED_VERSION	1
#define EAP_PEAP_SUPPORTED_VERSION	0

/**
 * EAP-TLS/TTLS packet format
 */
typedef struct __attribute__((packed)) {
	u_int8_t code;
	u_int8_t identifier;
	u_int16_t length;
	u_int8_t type;
	u_int8_t flags;
} eap_tls_packet_t;

METHOD(tls_eap_t, initiate, status_t,
	private_tls_eap_t *this, chunk_t *out)
{
	if (this->is_server)
	{
		eap_tls_packet_t pkt = {
			.type = this->type,
			.code = EAP_REQUEST,
			.flags = EAP_TLS_START,
		};
		switch (this->type)
		{
			case EAP_TTLS:
				pkt.flags |= EAP_TTLS_SUPPORTED_VERSION;
				break;
			case EAP_TNC:
				pkt.flags |= EAP_TNC_SUPPORTED_VERSION;
				break;
			case EAP_PEAP:
				pkt.flags |= EAP_PEAP_SUPPORTED_VERSION;
				break;
			default:
				break;
		}
		htoun16(&pkt.length, sizeof(eap_tls_packet_t));
		pkt.identifier = this->identifier;

		DBG2(DBG_IKE, "sending %N start packet", eap_type_names, this->type);
		*out = chunk_clone(chunk_from_thing(pkt));
		return NEED_MORE;
	}
	return FAILED;
}

/**
 * Process a received packet
 */
static status_t process_pkt(private_tls_eap_t *this, eap_tls_packet_t *pkt)
{
	u_int32_t msg_len;
	u_int16_t pkt_len;

	pkt_len = untoh16(&pkt->length);
	if (pkt->flags & EAP_TLS_LENGTH)
	{
		if (pkt_len < sizeof(eap_tls_packet_t) + sizeof(msg_len))
		{
			DBG1(DBG_TLS, "%N packet too short", eap_type_names, this->type);
			return FAILED;
		}
		msg_len = untoh32(pkt + 1);
		if (msg_len < pkt_len - sizeof(eap_tls_packet_t) - sizeof(msg_len) ||
			msg_len > MAX_TLS_MESSAGE_LEN)
		{
			DBG1(DBG_TLS, "invalid %N packet length", eap_type_names, this->type);
			return FAILED;
		}
		return this->tls->process(this->tls, (char*)(pkt + 1) + sizeof(msg_len),
						pkt_len - sizeof(eap_tls_packet_t) - sizeof(msg_len));
	}
	return this->tls->process(this->tls, (char*)(pkt + 1),
							  pkt_len - sizeof(eap_tls_packet_t));
}

/**
 * Build a packet to send
 */
static status_t build_pkt(private_tls_eap_t *this, chunk_t *out)
{
	char buf[this->frag_size];
	eap_tls_packet_t *pkt;
	size_t len, reclen;
	status_t status;
	char *kind;

	if (this->is_server)
	{
		this->identifier++;
	}
	pkt = (eap_tls_packet_t*)buf;
	pkt->code = this->is_server ? EAP_REQUEST : EAP_RESPONSE;
	pkt->identifier = this->identifier;
	pkt->type = this->type;
	pkt->flags = 0;

	switch (this->type)
	{
		case EAP_TTLS:
			pkt->flags |= EAP_TTLS_SUPPORTED_VERSION;
			break;
		case EAP_TNC:
			pkt->flags |= EAP_TNC_SUPPORTED_VERSION;
			break;
		case EAP_PEAP:
			pkt->flags |= EAP_PEAP_SUPPORTED_VERSION;
			break;
		default:
			break;
	}

	if (this->first_fragment)
	{
		pkt->flags |= EAP_TLS_LENGTH;
		len = sizeof(buf) - sizeof(eap_tls_packet_t) - sizeof(u_int32_t);
		status = this->tls->build(this->tls, buf + sizeof(eap_tls_packet_t) +
								  sizeof(u_int32_t), &len, &reclen);
	}
	else
	{
		len = sizeof(buf) - sizeof(eap_tls_packet_t);
		status = this->tls->build(this->tls, buf + sizeof(eap_tls_packet_t),
								  &len, &reclen);
	}
	switch (status)
	{
		case NEED_MORE:
			pkt->flags |= EAP_TLS_MORE_FRAGS;
			kind = "further fragment";
			if (this->first_fragment)
			{
				this->first_fragment = FALSE;
				kind = "first fragment";
			}
			break;
		case ALREADY_DONE:
			kind = "packet";
			if (!this->first_fragment)
			{
				this->first_fragment = TRUE;
				kind = "final fragment";
			}
			break;
		default:
			return status;
	}
	DBG2(DBG_TLS, "sending %N %s (%u bytes)",
		 eap_type_names, this->type, kind, len);
	if (reclen)
	{
		htoun32(pkt + 1, reclen);
		len += sizeof(u_int32_t);
		pkt->flags |= EAP_TLS_LENGTH;
	}
	len += sizeof(eap_tls_packet_t);
	htoun16(&pkt->length, len);
	*out = chunk_clone(chunk_create(buf, len));
	return NEED_MORE;
}

/**
 * Send an ack to request next fragment
 */
static chunk_t create_ack(private_tls_eap_t *this)
{
	eap_tls_packet_t pkt = {
		.code = this->is_server ? EAP_REQUEST : EAP_RESPONSE,
		.type = this->type,
	};

	if (this->is_server)
	{
		this->identifier++;
	}
	pkt.identifier = this->identifier;
	htoun16(&pkt.length, sizeof(pkt));

	switch (this->type)
	{
		case EAP_TTLS:
			pkt.flags |= EAP_TTLS_SUPPORTED_VERSION;
			break;
		case EAP_TNC:
			pkt.flags |= EAP_TNC_SUPPORTED_VERSION;
			break;
		case EAP_PEAP:
			pkt.flags |= EAP_PEAP_SUPPORTED_VERSION;
			break;
		default:
			break;
	}
	DBG2(DBG_TLS, "sending %N acknowledgement packet",
		 eap_type_names, this->type);
	return chunk_clone(chunk_from_thing(pkt));
}

METHOD(tls_eap_t, process, status_t,
	private_tls_eap_t *this, chunk_t in, chunk_t *out)
{
	eap_tls_packet_t *pkt;
	status_t status;

	if (++this->processed > this->max_msg_count)
	{
		DBG1(DBG_IKE, "%N packet count exceeded (%d > %d)",
			 eap_type_names, this->type,
			 this->processed, this->max_msg_count);
		return FAILED;
	}

	pkt = (eap_tls_packet_t*)in.ptr;
	if (in.len < sizeof(eap_tls_packet_t) || untoh16(&pkt->length) != in.len)
	{
		DBG1(DBG_IKE, "invalid %N packet length", eap_type_names, this->type);
		return FAILED;
	}

	/* update EAP identifier */
	this->identifier = pkt->identifier;

	if (pkt->flags & EAP_TLS_START)
	{
		if (this->type == EAP_TTLS || this->type == EAP_TNC ||
			this->type == EAP_PEAP)
		{
			DBG1(DBG_TLS, "%N version is v%u", eap_type_names, this->type,
				 pkt->flags & EAP_TTLS_VERSION);
		}
	}
	else
	{
		if (in.len == sizeof(eap_tls_packet_t))
		{
			DBG2(DBG_TLS, "received %N acknowledgement packet",
				 eap_type_names, this->type);
			status = build_pkt(this, out);
			if (status == INVALID_STATE && this->tls->is_complete(this->tls))
			{
				return SUCCESS;
			}
			return status;
		}
		status = process_pkt(this, pkt);
		switch (status)
		{
			case NEED_MORE:
				break;
			case SUCCESS:
				return this->tls->is_complete(this->tls) ? SUCCESS : FAILED;
			default:
				return status;
		}
	}
	status = build_pkt(this, out);
	switch (status)
	{
		case INVALID_STATE:
			*out = create_ack(this);
			return NEED_MORE;
		case FAILED:
			if (!this->is_server)
			{
				*out = create_ack(this);
				return NEED_MORE;
			}
			return FAILED;
		default:
			return status;
	}
}

METHOD(tls_eap_t, get_msk, chunk_t,
	private_tls_eap_t *this)
{
	return this->tls->get_eap_msk(this->tls);
}

METHOD(tls_eap_t, get_identifier, u_int8_t,
	private_tls_eap_t *this)
{
	return this->identifier;
}

METHOD(tls_eap_t, set_identifier, void,
	private_tls_eap_t *this, u_int8_t identifier)
{
	this->identifier = identifier;
}

METHOD(tls_eap_t, destroy, void,
	private_tls_eap_t *this)
{
	this->tls->destroy(this->tls);
	free(this);
}

/**
 * See header
 */
tls_eap_t *tls_eap_create(eap_type_t type, tls_t *tls, size_t frag_size,
						  int max_msg_count)
{
	private_tls_eap_t *this;

	if (!tls)
	{
		return NULL;
	}

	INIT(this,
		.public = {
			.initiate = _initiate,
			.process = _process,
			.get_msk = _get_msk,
			.get_identifier = _get_identifier,
			.set_identifier = _set_identifier,
			.destroy = _destroy,
		},
		.type = type,
		.is_server = tls->is_server(tls),
		.first_fragment = TRUE,
		.frag_size = frag_size,
		.max_msg_count = max_msg_count,
		.tls = tls,
	);

	if (this->is_server)
	{
		do
		{	/* start with non-zero random identifier */
			this->identifier = random();
		}
		while (!this->identifier);
	}

	return &this->public;
}
