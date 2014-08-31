/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014 Patricio Zavolinsky
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#include "PacketHandlers.hpp"

#include <stdio.h>
#include <netinet/in.h>
#include <linux/netfilter.h> 
#include <netinet/ip.h>

using namespace NetFilter;

void CompositeHandler::add(NetFilter::PacketHandler& handler)
{
	_handlers.push_back(&handler);
}
int CompositeHandler::handlePacket(NetFilter::Queue& queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad)
{
	for (list_t::iterator it = _handlers.begin(); it != _handlers.end(); ++it)
	{
		int ret = (*it)->handlePacket(queue, nfmsg, nfad);
		if (ret < 0)
			return ret;
	}
	return 0;
}

// ========================================================================= //
EchoHandler::EchoHandler(const char* prefix) : _prefix(prefix) {}

int EchoHandler::handlePacket(Queue& queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad)
{
	int id = 0;

	printf("%s", _prefix.c_str());

	struct nfqnl_msg_packet_hdr* ph = nfq_get_msg_packet_hdr(nfad);
	if (ph)
	{
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ", ntohs(ph->hw_protocol), ph->hook, id);
	}
	
	struct nfqnl_msg_packet_hw* hwph = nfq_get_packet_hw(nfad);
	if (hwph)
	{
			int i, hlen = ntohs(hwph->hw_addrlen);
			printf("hw_src_addr=");
			for (i = 0; i < hlen-1; i++)
					printf("%02x:", hwph->hw_addr[i]);
			printf("%02x ", hwph->hw_addr[hlen-1]);
	}
	u_int32_t mark = nfq_get_nfmark(nfad);
	if (mark)
			printf("mark=%u ", mark);
	u_int32_t ifi = nfq_get_indev(nfad);
	if (ifi)
			printf("indev=%u ", ifi);
	ifi = nfq_get_outdev(nfad);
	if (ifi)
			printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(nfad);
	if (ifi)
			printf("physindev=%u ", ifi);
	ifi = nfq_get_physoutdev(nfad);
	if (ifi)
			printf("physoutdev=%u ", ifi);
	unsigned char *data;
	int ret = nfq_get_payload(nfad, &data);
	if (ret >= 0)
			printf("payload_len=%d ", ret);
	
	if ((unsigned int)ret >= sizeof(struct iphdr))
	{
		struct iphdr* ip = (struct iphdr*) data;
		
		u_int16_t flags = ntohs(ip->frag_off);
		
			printf("\n%s    ip { version=%d, ihl=%d, tos=%d, len=%d, id=%d, flags=%d frag_off=%d, ttl=%d, protocol=%d, check=%d } ",
				_prefix.c_str(),
				ip->version, ip->ihl, ip->tos, ntohs(ip->tot_len), ip->id, flags >> 13, flags & 0x1FFF, ip->ttl, ip->protocol, ntohs(ip->check)
			);
	}
	fputc('\n', stdout);
	
	return 0;
}

// ========================================================================= //

int AcceptHandler::handlePacket(NetFilter::Queue& queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr* ph = nfq_get_msg_packet_hdr(nfad);
	if (ph)
		id = ntohl(ph->packet_id);
	queue.setVerdict(id, NF_ACCEPT, 0, NULL);
	return 0;
}

// ========================================================================= //

static uint16_t checksum(const uint16_t* buf, unsigned int nbytes)
{
	uint32_t sum = 0;

	for (; nbytes > 1; nbytes -= 2)
	{
		sum += *buf++;
	}

	if (nbytes == 1)
	{
		sum += *(unsigned char*) buf;
	}

	sum  = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);

	return ~sum;
}

MangleHandler::MangleHandler(PacketMangler& mangler) : _mangler(mangler) {}
int MangleHandler::handlePacket(NetFilter::Queue& queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr* ph = nfq_get_msg_packet_hdr(nfad);
	if (ph)
		id = ntohl(ph->packet_id);
	
	unsigned char *data;
	
	int ret = nfq_get_payload(nfad, &data);
	
	u_int32_t data_len = 0;
	unsigned char *buf = NULL;
	
	if ((unsigned int)ret >= sizeof(struct iphdr))
	{
		struct iphdr* ip = (struct iphdr*) data;
		
		_mangler.manglePacket(*ip);
		
		// Recompute checksum
		ip->check = 0;
		ip->check = checksum((const uint16_t*) ip, ip->ihl*4);
		buf = (unsigned char*) data;
		data_len = ret;
	}
	
	queue.setVerdict(id, NF_ACCEPT, data_len, buf);
	
	return 0;
}
