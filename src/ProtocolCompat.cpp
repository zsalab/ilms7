/*******************************************************************************
 * Copyright (C) 2004-2011 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 *  - Neither the name of Intel Corporation. nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL Intel Corporation. OR THE CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *******************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#include <arpa/inet.h>
#include <netinet/in.h>
#include <cerrno>
#include "Protocol.h"
#include "LMS_if_compat.h"
#include "Lock.h"
#include "ATNetworkTool.h"

void Protocol::_LmeReceiveCompat(char *buffer, unsigned int len, int *status)
{
	int error = 0;

	PRINT("[Compat]MEI received %d bytes (msg type 0x%02x)\n", len, buffer[0]);
	*status = 0;

	switch (buffer[0]) {
	case LMS_MESSAGE_TYPE_OPEN_CONNECTION_EX:
		{
			SOCKET s_new = INVALID_SOCKET;
			LMS_OPEN_CONNECTION_EX_MESSAGE *msg =
			    (LMS_OPEN_CONNECTION_EX_MESSAGE *)buffer;

			int type;
			switch (msg->Protocol) {
			case LMS_PROTOCOL_TYPE_UDP_IPV4:
				type = SOCK_DGRAM;
				break;
			case LMS_PROTOCOL_TYPE_TCP_IPV4:
			default:
				type = SOCK_STREAM;
				break;
			}

			if ((msg->Flags & HOSTNAME_BIT) != 0) {
				PRINT("[Compat]Got client connection request %d for host %s, port %d\n",
					msg->ConnectionId,
					msg->Host,
					ntohs(msg->HostPort));

				s_new = ATNetworkTool::Connect(
					(const char *)msg->Host,
					ntohs(msg->HostPort),
					error, PF_INET, type);
			} else {
				PRINT("[Compat]Got client connection request %d for IP %s, port %d\n",
					msg->ConnectionId,
					inet_ntoa(*((struct in_addr *)msg->Host)),
					ntohs(msg->HostPort));

				s_new = ATNetworkTool::Connect(
					inet_ntoa(*((struct in_addr *)msg->Host)),
					ntohs(msg->HostPort),
					error, PF_INET, type);
			}

			if (s_new == INVALID_SOCKET) {
				*status = 1;
				break;
			}

			Channel *c = new Channel(NULL, s_new);
			c->SetRecipientChannel(msg->ConnectionId);
			c->SetStatus(Channel::OPEN);
			c->AddBytesTxWindow(1024);
			{
				Lock l(_channelsLock);
				unsigned int newChannelID = _getNewChannel();
				if (newChannelID == ILLEGAL_CHANNEL)
				{
				    *status = 1;
				    PRINT("Unable to open direct allocate a new channel.\n");
				    return;
				}
				c->SetSenderChannel(newChannelID);
				_socketToChannel[msg->ConnectionId] = c;
				_channelToSocket[newChannelID] = msg->ConnectionId;
			}

			_signalSelect();
		}
		break;

	case LMS_MESSAGE_TYPE_CLOSE_CONNECTION:
		{
			LMS_CLOSE_CONNECTION_MESSAGE *msg =
			    (LMS_CLOSE_CONNECTION_MESSAGE *)buffer;

			PRINT("[Compat]received close connection msg from MEI for connection %d\n", msg->ConnectionId);

			Lock l(_channelsLock);

			SocketToChannelMap::iterator it = _socketToChannel.find(msg->ConnectionId);
			if (it != _socketToChannel.end()) {
			        Channel *c = it->second;
			        _channelToSocket.erase(c->GetSenderChannel());
				_socketToChannel.erase(msg->ConnectionId);
				_closeMChannel(c);
			}
		}
		break;

	case LMS_MESSAGE_TYPE_SEND_DATA:
		{
			LMS_SEND_DATA_MESSAGE *msg =
			    (LMS_SEND_DATA_MESSAGE *)buffer;

			Lock l(_channelsLock);
			
			SocketToChannelMap::iterator it = _socketToChannel.find(msg->ConnectionId);
			
			if (it != _socketToChannel.end()) {
				PRINT("[Compat]sending %d bytes from MEI connection %d to socket %d\n", ntohs(msg->DataLength), msg->ConnectionId, it->second->GetSocket());
				if (-1 == _send(it->second->GetSocket(), (char *)msg->Data, ntohs(msg->DataLength), error)) {
					if (EPIPE == error) {
					         Channel *c = it->second;
					         _channelToSocket.erase(c->GetSenderChannel());
					         _socketToChannel.erase(msg->ConnectionId);
						_closeMChannel(it->second);
						*status = 1;
					}
				}
			}
		}
		break;

	case LMS_MESSAGE_TYPE_IP_FQDN:
		if (_updateIPFQDN((const char *)((LMS_IP_FQDN_MESSAGE *)buffer)->FQDN) != 0) {
			ERROR("[Compat]Error: failed to update IP/FQDN info\n");
		}
		break;

	default:
		*status = 1;
		break;
	}
}

