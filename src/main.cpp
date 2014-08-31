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
#include "PacketHandlers.hpp"

#include <iostream>
#include <netinet/ip.h>

using namespace NetFilter;
using std::cerr;
using std::endl;

// This example shows how to update the TTL of IP packets. These changes to the
// IP header could be exploited to transport steganographic messages.
class StegMangler : public PacketMangler
{
	public:
		void manglePacket(struct iphdr& ipHeader)
		{
			// Let them know the answer to the Ultimate Question of Life,
			// the Universe, and Everything.
			ipHeader.ttl = 42;
		}
};

int main()
{
	try
	{
		// Create a packet-handling library bound to the IP address family
		Library lib;
		lib.bind(AF_INET);
		
		// -- Configure packet handlers --- //
		CompositeHandler handlers;
		
		// Echo incoming packets
		EchoHandler echoHandler("[BEFORE] ");
		handlers.add(echoHandler);
		
		// Mangle incoming packets
		StegMangler mangler;
		MangleHandler mangleHandler(mangler);
		handlers.add(mangleHandler);
		
		// Echo mangled packets
		EchoHandler echoMangledHandler("[AFTER]  ");
		handlers.add(echoMangledHandler);
		// -------------------------------- //
		
		// Create queue number 0, configured to use the handler stack
		Queue queue(lib, 0, handlers);
		
		{ // Set iptables rules (process ICMP messages)
			
			IpTablesScope scope("OUTPUT -p icmp -j NFQUEUE --queue-num 0");
			cerr << "    === Hit CTRL+C or kill -INT to stop ===" << endl;
			lib.loop();
			
		} // Reset iptable rules
	}
	catch (const char* s)
	{
		cerr << s << " (" << nfq_errno << ")" << endl;
		return -1;
	}
	
	return 0;
}
