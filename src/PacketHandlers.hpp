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
#ifndef _PACKETHANDLERS_HPP__
#define _PACKETHANDLERS_HPP__

#include "NetFilterQueue.hpp"
#include <list>
#include <string>

/** Composite packet handler.
 * This is a classic composite pattern applied to the PacketHandler class.
 * A composite packet handler can be thought of as a packet handling
 * pipeline.
 */
class CompositeHandler : public NetFilter::PacketHandler
{
	public:
		void add(NetFilter::PacketHandler& handler);
		int handlePacket(NetFilter::Queue& queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad);
	protected:
		typedef std::list<NetFilter::PacketHandler*> list_t;
		list_t _handlers;
};

/** Echo packet handler.
 * This handler echoes the packet details to stderr.
 */
class EchoHandler : public NetFilter::PacketHandler
{
	public:
		EchoHandler(const char* prefix);
		int handlePacket(NetFilter::Queue& queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad);
	protected:
		std::string _prefix;
};

/** Accept all packet handler.
 * This handler accepts every packet.
 */
class AcceptHandler : public NetFilter::PacketHandler
{
	public:
		int handlePacket(NetFilter::Queue& queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad);
};

/** Abstract packet mangler. This class is resposible for changing the packet
 * data.
 */
class PacketMangler
{
	public:
		/** Hook (override) this method to change the header of IP packets.
		 */
		virtual void manglePacket(struct iphdr& ipHeader) = 0;
};

/** Mangle packet handler.
 * This handler applies a PacketMangler, recomputes the packet checksum and
 * accepts the packet.
 */
class MangleHandler : public NetFilter::PacketHandler
{
	public:
		/**
		 * Creates a new packet mangler handler.
		 * \param mangler The packet mangler.
		 */
		MangleHandler(PacketMangler& mangler);
		int handlePacket(NetFilter::Queue& queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad);
	protected:
		PacketMangler& _mangler;
};

#endif
