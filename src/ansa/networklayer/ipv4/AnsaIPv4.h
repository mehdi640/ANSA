// Copyright (C) 2013 Brno University of Technology (http://nes.fit.vutbr.cz/ansa)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
/**
 * @file AnsaIPv4.h
 * @date 21.10.2011
 * @author Veronika Rybova, Vladimir Vesely (mailto:ivesely@fit.vutbr.cz)
 * @brief IPv4 implementation with changes for multicast
 * @details File contains extension of class IP, which can work also with multicast data and multicast
 */

#ifndef __INET_ANSAIPV4_H
#define __INET_ANSAIPV4_H

#include "INETDefs.h"
#include "IPv4Datagram.h"
#include "IPv4.h"

/**
 * @brief Class is extension of the IP protocol implementation for vrrpv2.
 * @details It extends IPv4 routing decision with vforwarderId.
 *
 * It also contains some kludges for multicast routing:
 *   - to add/remove multicast listeners when fake IGMP messages are received
 *   - to refresh the string representation of the multicast routing table
 */
class INET_API AnsaIPv4 : public IPv4
{
    protected:
        virtual void handlePacketFromNetwork(IPv4Datagram *datagram, InterfaceEntry *fromIE);
        virtual void forwardMulticastPacket(IPv4Datagram *datagram, InterfaceEntry *fromIE);
        virtual void routeUnicastPacket(IPv4Datagram *datagram, InterfaceEntry *destIE, IPv4Address destNextHopAddr);
        virtual void handleMessageFromHL(cPacket *msg);

        virtual void fragmentAndSend(IPv4Datagram *datagram, InterfaceEntry *ie, IPv4Address nextHopAddr, int vforwarder);
        virtual void sendDatagramToOutput(IPv4Datagram *datagram, InterfaceEntry *ie, IPv4Address nextHopAddr, int vforwarderId);
        int getVirtualForwarderId(InterfaceEntry *ie, MACAddress addr);

    public:
        AnsaIPv4() {}
};


#endif
