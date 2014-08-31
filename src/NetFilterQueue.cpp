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
#include "NetFilterQueue.hpp"

#include <iostream>
#include <stdlib.h>
#include <sys/select.h>
#include <memory.h>
#include <signal.h>
#include <netinet/in.h>
#include <linux/netfilter.h>

using namespace NetFilter;
using std::cerr;
using std::endl;

Queue::Queue(const Library& lib, u_int16_t num, PacketHandler& packetHandler) : _packetHandler(packetHandler)
{
	_handle = nfq_create_queue(lib._handle, num, _callback, this);
	if (!_handle) throw "Cannot create queue";
	
	if (nfq_set_mode(_handle, NFQNL_COPY_PACKET, 0xffff) < 0)
	{
		nfq_destroy_queue(_handle);
		throw "Cannot set COPY_PACKET mode";
	}
	cerr << "[NF QUEUE] created" << endl;
}
Queue::~Queue()
{
	nfq_destroy_queue(_handle);
	cerr << "[NF QUEUE] destroyed" << endl;
}

int Queue::_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *data)
{
	Queue* queue = reinterpret_cast<Queue*>(data);
	return queue->_packetHandler.handlePacket(*queue, nfmsg, nfad);
}

void Queue::setVerdict(u_int32_t id, u_int32_t verdict, u_int32_t data_len, const unsigned char *buf)
{
	nfq_set_verdict(_handle, id, verdict, data_len, buf);
}


Library::Library()
{
	_handle = nfq_open();
	if (!_handle) throw "Cannot open queue";
	cerr << "[NF LIB]   created" << endl;
}
Library::~Library()
{
	nfq_close(_handle);
	cerr << "[NF LIB]   destroyed" << endl;
}
void Library::bind(u_int16_t protocolFamily)
{
	if (nfq_unbind_pf(_handle, protocolFamily) < 0)
		throw "Cannot unbind protocol family";
	if (nfq_bind_pf(_handle, protocolFamily) < 0)
		throw "Cannot bind protocol family";
}
void Library::loop()
{
	// Block INT signals
	{
		sigset_t intmask;
		sigemptyset(&intmask);
		sigaddset(&intmask, SIGINT);
		if (sigprocmask(SIG_BLOCK, &intmask, NULL) == -1)
			throw "Cannot block INT signal";
	}
	
	// Ignore INT signals
	{
		struct sigaction sa;
		memset(&sa, 0, sizeof(sa));
		sa.sa_flags = 0;
		sa.sa_handler = _sigint;
		sigemptyset(&sa.sa_mask);
		if (sigaction(SIGINT, &sa, NULL) == -1)
			throw "Cannot set INT handler";
	}
	
	sigset_t emptymask;
	sigemptyset(&emptymask);
	
	char buf[4096] __attribute__ ((aligned));
	int fd = nfq_fd(_handle);
	fd_set rfds;
	
	for (;;)
	{
		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);
		
		if (pselect(fd+1, &rfds, NULL, NULL, NULL, &emptymask) <= 0)
			break;
		
		if (!FD_ISSET(fd, &rfds))
			break;
		
		int rv = recv(fd, buf, sizeof(buf), 0);
		if (rv < 0)
			break;
		
		nfq_handle_packet(_handle, buf, rv);
	}
}

IpTablesScope::IpTablesScope(const char* rule) : _rule(rule)
{
	std::string cmd("iptables -A ");
	cmd += _rule;
	if (system(cmd.c_str()))
		throw "Cannot set iptables rule";
	cerr << "[IPTABLES] " << cmd << endl;
}
IpTablesScope::~IpTablesScope()
{
	std::string cmd("iptables -D ");
	cmd += _rule;
	if (system(cmd.c_str()))
		cerr << "Cannot reset iptables rule" << endl;
	else
		cerr << "[IPTABLES] " << cmd << endl;
}
