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
#ifndef _NETFILTERQUEUE_HPP__
#define _NETFILTERQUEUE_HPP__

#include <string>

#include <stdint.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

namespace NetFilter
{
	/** NetFilterQueue (nfq) library wrapper providing RAII.
	 * See: http://www.netfilter.org/projects/libnetfilter_queue/doxygen/group__LibrarySetup.html
	 */
	class Library
	{
		public:
			/** Opens a connection with nfq.
			 */
			Library();
			
			/** Closes connection with nfq.
			 */
			~Library();
			
			/** Binds nfq to a specific address/protocol family (e.g. AF_INET).
			 */
			void bind(u_int16_t protocolFamily);
			
			/** Processes packets, exits when interrupted with a SIGINT.
			 */
			void loop();
			
		private:
			struct nfq_handle* _handle;
			friend class Queue;
			
			static void _sigint(int sig) {}
	};
	
	class Queue;
	
	/** Abstract packet handler. This class is responsible for inspecting
	 * packets and setting a packet verdict.
	 * 
	 * \note Packet handlers can be composed into a CompositeHandler.
	 *       For simple (read-only) packet handlers the recommented approach
	 *       is to create a CompositeHandler including the packet handler
	 *       followed by either a MangleHandler or an AcceptHandler.
	 */
	class PacketHandler
	{
		public:
			/**
			* Handles a packet and sets its verdict.
			* Note: after inspecting the packet call queue.setVerdict() to set
			* the packet verdict.
			*
			* \param queue Queue instance used to set the packet verdict
			* \param nfmsg Message object that contains the packet
			* \param nfad Netlink packet data handle
			*
			* \return 0 if the packet was handled, -1 otherwise.
			* 
			*/
			virtual int handlePacket(Queue& queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad) = 0;
	};
	
	/** Nfq queuewrapper providing RAII and a packet handling pipeline.
	 */
	class Queue
	{
		public:
			/**
			 * Creates a new nfq queue identified by #num using the specified
			 * packet handling pipeline.
			 *
			 * \param lib           Reference to a Library nfq wrapper.
			 * \param num           Queue numeric id (used in iptables rules).
			 * \param packetHandler Packet handler pipeline that will process
			 *                      packets and set their verdict.
			 */
			Queue(const Library& lib, u_int16_t num, PacketHandler& packetHandler);
			
			/** Destroys the nfq queue.
			 */
			~Queue();
			
			/**
			 * Issues a verdict on a packet.
			 * See: http://www.netfilter.org/projects/libnetfilter_queue/doxygen/group__Queue.html#gae36aee5b74d0c88d2f8530e356f68b79
			 * 
			 * \param id       ID assigned to packet by netfilter.
			 * \param verdict  Verdict to return to netfilter (NF_ACCEPT, NF_DROP).
			 * \param data_len Number of bytes of data pointed to by buf.
			 * \param buf      The buffer that contains the packet data.
			 * 
			 * Note: if the packet was not changed through a packet mangler, #buf can be NULL and data_len 0.
			 */
			void setVerdict(u_int32_t id, u_int32_t verdict, u_int32_t data_len, const unsigned char *buf);

		private:
			struct nfq_q_handle* _handle;
			
			PacketHandler& _packetHandler;
			
			static int _callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *data);
	};
	
	
	/** iptables command-line wrapper providing RAII.
	 */
	class IpTablesScope
	{
		public:
			/** Adds the iptables rule specified.
			 */
			IpTablesScope(const char* rule);
			/** Deletes the iptables rule.
			 */
			~IpTablesScope();
			
		private:
			std::string _rule;
	};
	
} // NetFilter

#endif
