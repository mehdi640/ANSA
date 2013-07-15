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
 * @file AnsaIPv4.cc
 * @date 10.10.2011
 * @author Veronika Rybova,Tomas Prochazka (mailto:xproch21@stud.fit.vutbr.cz), Vladimir Vesely (mailto:ivesely@fit.vutbr.cz)
 * @brief IPv4 implementation with changes for multicast
 * @details File contains reimplementation of some methods in IP class,
 * which can work also with multicast data and multicast
 */


#include <omnetpp.h>
#include "AnsaIPv4.h"

#include "ICMPMessage_m.h"
#include "IPv4ControlInfo.h"
#include "IPv4InterfaceData.h"
#include "IRoutingTable.h"
#include "NotificationBoard.h"
#include "AnsaRoutingTable.h"
#include "AnsaInterfaceEntry.h"
#include "AnsaIPv4RoutingDecision_m.h"

Define_Module(AnsaIPv4);

void AnsaIPv4::handlePacketFromNetwork(IPv4Datagram *datagram, InterfaceEntry *fromIE)
{
    ASSERT(datagram);
    ASSERT(fromIE);

    IPv4Address destAddr = datagram->getDestAddress();

    if (!datagram->hasBitError() && !fromIE->isLoopback() && destAddr.isMulticast())
    {
        //FIXME temporary hack to catch "IGMP" for initialization PIM Join/Prune (*,G) PIM-SM
        if (datagram->getTransportProtocol() == IP_PROT_IGMP)
        {
            EV << "AnsaIPv4::handlePacketFromNetwork - IGMP packet received" << endl;

            if (fromIE->ipv4Data()->hasMulticastListener(destAddr))
                fromIE->ipv4Data()->removeMulticastListener(destAddr);
            else
                fromIE->ipv4Data()->addMulticastListener(destAddr);
        }
    }

    IPv4::handlePacketFromNetwork(datagram, fromIE);
}

// FIXME: generateShowIPMRoute() shold only be called when there is a change in the multicast routes.
//        I don't know why it is not an internal method in AnsaRoutingTable.
void AnsaIPv4::forwardMulticastPacket(IPv4Datagram *datagram, InterfaceEntry *fromIE)
{
    IPv4::forwardMulticastPacket(datagram, fromIE);

    // refresh output in MRT
    check_and_cast<AnsaRoutingTable*>(dynamic_cast<cObject*>(rt))->generateShowIPMroute();
}

void AnsaIPv4::handleMessageFromHL(cPacket *msg)
{
    // if no interface exists, do not send datagram
    if (ift->getNumInterfaces() == 0)
    {
        EV << "No interfaces exist, dropping packet\n";
        numDropped++;
        delete msg;
        return;
    }

    // encapsulate and send
    IPv4Datagram *datagram = dynamic_cast<IPv4Datagram *>(msg);
    IPv4ControlInfo *controlInfo = NULL;
    //FIXME dubious code, remove? how can the HL tell IP whether it wants tunneling or forwarding?? --Andras
    if (datagram) // if HL sends an IPv4Datagram, route the packet
    {
        // Dsr routing, Dsr is a HL protocol and send IPv4Datagram
        if (datagram->getTransportProtocol()==IP_PROT_DSR)
        {
            controlInfo = check_and_cast<IPv4ControlInfo*>(datagram->removeControlInfo());
        }
    }
    else
    {
        // encapsulate
        controlInfo = check_and_cast<IPv4ControlInfo*>(msg->removeControlInfo());
        datagram = encapsulate(msg, controlInfo);
    }

    // extract requested interface and next hop
    InterfaceEntry *destIE = NULL;
    IPv4Address nextHopAddress = IPv4Address::UNSPECIFIED_ADDRESS;
    int vforwarder = -1;
    bool multicastLoop = true;

    if (controlInfo!=NULL)
    {
        destIE = ift->getInterfaceById(controlInfo->getInterfaceId());
        nextHopAddress = controlInfo->getNextHopAddr();
        multicastLoop = controlInfo->getMulticastLoop();

        if (destIE && dynamic_cast<AnsaInterfaceEntry *>(destIE))
        {
            AnsaInterfaceEntry* ieVF = dynamic_cast<AnsaInterfaceEntry *>(destIE);
            vforwarder = ieVF->getVirtualForwarderId(controlInfo->getMacSrc());
        }
    }

    delete controlInfo;

    // send
    IPv4Address &destAddr = datagram->getDestAddress();

    EV << "Sending datagram `" << datagram->getName() << "' with dest=" << destAddr << "\n";

    if (datagram->getDestAddress().isMulticast())
    {
        destIE = determineOutgoingInterfaceForMulticastDatagram(datagram, destIE);

        // loop back a copy
        if (multicastLoop && (!destIE || !destIE->isLoopback()))
        {
            InterfaceEntry *loopbackIF = ift->getFirstLoopbackInterface();
            if (loopbackIF)
                fragmentAndSend(datagram->dup(), loopbackIF, destAddr, vforwarder);
        }

        if (destIE)
        {
            numMulticast++;
            fragmentAndSend(datagram, destIE, destAddr, vforwarder);
        }
        else
        {
            EV << "No multicast interface, packet dropped\n";
            numUnroutable++;
            delete datagram;
        }
    }
    else // unicast and broadcast
    {
#ifdef WITH_MANET
        if (manetRouting)
            sendRouteUpdateMessageToManet(datagram);
#endif
        // check for local delivery
        if (rt->isLocalAddress(destAddr))
        {
            EV << "local delivery\n";
            if (destIE)
                EV << "datagram destination address is local, ignoring destination interface specified in the control info\n";

            destIE = ift->getFirstLoopbackInterface();
            ASSERT(destIE);
            fragmentAndSend(datagram, destIE, destAddr, vforwarder);
        }
        else if (destAddr.isLimitedBroadcastAddress() || rt->isLocalBroadcastAddress(destAddr))
            routeLocalBroadcastPacket(datagram, destIE);
        else
            routeUnicastPacket(datagram, destIE, nextHopAddress);
    }
}


void AnsaIPv4::routeUnicastPacket(IPv4Datagram *datagram, InterfaceEntry *destIE, IPv4Address destNextHopAddr)
{
    IPv4Address destAddr = datagram->getDestAddress();

    EV << "Routing datagram `" << datagram->getName() << "' with dest=" << destAddr << ": ";

    IPv4Address nextHopAddr;
    // if output port was explicitly requested, use that, otherwise use IPv4 routing
    if (destIE)
    {
        EV << "using manually specified output interface " << destIE->getName() << "\n";
        // and nextHopAddr remains unspecified
        if (manetRouting && !destNextHopAddr.isUnspecified())
           nextHopAddr = destNextHopAddr;  // Manet DSR routing explicit route
        // special case ICMP reply
        else if (destIE->isBroadcast())
        {
            // if the interface is broadcast we must search the next hop
            const IPv4Route *re = rt->findBestMatchingRoute(destAddr);
            if (re && (re->getSource() != IPv4Route::MANET || re->getDestination()==destAddr) &&
                    re->getInterface() == destIE)
                nextHopAddr = re->getGateway();
        }
    }
    else
    {
        // use IPv4 routing (lookup in routing table)
        //    FIXME MANET routes should use 255.255.255.255 netmask,
        //          to eliminate the equality check below.
        const IPv4Route *re = rt->findBestMatchingRoute(destAddr);
        if (re && (re->getSource() != IPv4Route::MANET || re->getDestination() == destAddr))
        {
            destIE = re->getInterface();
            nextHopAddr = re->getGateway();
        }
    }

    if (!destIE) // no route found
    {
#ifdef WITH_MANET
            if (manetRouting)
               sendNoRouteMessageToManet(datagram);
            else
            {
#endif
                EV << "unroutable, sending ICMP_DESTINATION_UNREACHABLE\n";
                numUnroutable++;
                icmpAccess.get()->sendErrorMessage(datagram, ICMP_DESTINATION_UNREACHABLE, 0);
#ifdef WITH_MANET
            }
#endif
    }
    else // fragment and send
    {
        int vforwarder = -1;
        if (dynamic_cast<AnsaInterfaceEntry *>(destIE))
        {
            vforwarder = dynamic_cast<AnsaInterfaceEntry *>(destIE)->getVirtualForwarderId(datagram->getSrcAddress());
        }

        EV << "output interface is " << destIE->getName() << ", next-hop address: " << nextHopAddr << "\n";
        numForwarded++;
        fragmentAndSend(datagram, destIE, nextHopAddr, vforwarder);
    }
}

void AnsaIPv4::sendDatagramToOutput(IPv4Datagram *datagram, InterfaceEntry *ie, IPv4Address nextHopAddr, int vforwarderId)
{
    if (vforwarderId == -1)
    {
        IPv4::sendDatagramToOutput(datagram,ie, nextHopAddr);
        return;
    }

    AnsaInterfaceEntry* ieVF = dynamic_cast<AnsaInterfaceEntry *>(ie);
    delete datagram->removeControlInfo();
    AnsaIPv4RoutingDecision *routingDecision = new AnsaIPv4RoutingDecision();
    routingDecision->setInterfaceId(ieVF->getInterfaceId());
    routingDecision->setNextHopAddr(nextHopAddr);
    routingDecision->setVforwarderId(vforwarderId);
    datagram->setControlInfo(routingDecision);
    send(datagram, queueOutGate);
}

void AnsaIPv4::fragmentAndSend(IPv4Datagram *datagram, InterfaceEntry *ie, IPv4Address nextHopAddr, int vforwarder)
{
    // fill in source address
    if (datagram->getSrcAddress().isUnspecified())
        datagram->setSrcAddress(ie->ipv4Data()->getIPAddress());

    // hop counter decrement; but not if it will be locally delivered
    if (!ie->isLoopback())
        datagram->setTimeToLive(datagram->getTimeToLive()-1);

    // hop counter check
    if (datagram->getTimeToLive() < 0)
    {
        // drop datagram, destruction responsibility in ICMP
        EV << "datagram TTL reached zero, sending ICMP_TIME_EXCEEDED\n";
        icmpAccess.get()->sendErrorMessage(datagram, ICMP_TIME_EXCEEDED, 0);
        numDropped++;
        return;
    }

    int mtu = ie->getMTU();

    // check if datagram does not require fragmentation
    if (datagram->getByteLength() <= mtu)
    {
        sendDatagramToOutput(datagram, ie, nextHopAddr, vforwarder);
        return;
    }

    // if "don't fragment" bit is set, throw datagram away and send ICMP error message
    if (datagram->getDontFragment())
    {
        EV << "datagram larger than MTU and don't fragment bit set, sending ICMP_DESTINATION_UNREACHABLE\n";
        icmpAccess.get()->sendErrorMessage(datagram, ICMP_DESTINATION_UNREACHABLE,
                                                     ICMP_FRAGMENTATION_ERROR_CODE);
        numDropped++;
        return;
    }

    // optimization: do not fragment and reassemble on the loopback interface
    if (ie->isLoopback())
    {
        sendDatagramToOutput(datagram, ie, nextHopAddr, vforwarder);
        return;
    }

    // FIXME some IP options should not be copied into each fragment, check their COPY bit
    int headerLength = datagram->getHeaderLength();
    int payloadLength = datagram->getByteLength() - headerLength;
    int fragmentLength = ((mtu - headerLength) / 8) * 8; // payload only (without header)
    int offsetBase = datagram->getFragmentOffset();

    int noOfFragments = (payloadLength + fragmentLength - 1)/ fragmentLength;
    EV << "Breaking datagram into " << noOfFragments << " fragments\n";

    // create and send fragments
    std::string fragMsgName = datagram->getName();
    fragMsgName += "-frag";

    for (int offset=0; offset < payloadLength; offset+=fragmentLength)
    {
        bool lastFragment = (offset+fragmentLength >= payloadLength);
        // length equal to fragmentLength, except for last fragment;
        int thisFragmentLength = lastFragment ? payloadLength - offset : fragmentLength;

        // FIXME is it ok that full encapsulated packet travels in every datagram fragment?
        // should better travel in the last fragment only. Cf. with reassembly code!
        IPv4Datagram *fragment = (IPv4Datagram *) datagram->dup();
        fragment->setName(fragMsgName.c_str());

        // "more fragments" bit is unchanged in the last fragment, otherwise true
        if (!lastFragment)
            fragment->setMoreFragments(true);

        fragment->setByteLength(headerLength + thisFragmentLength);
        fragment->setFragmentOffset(offsetBase + offset);

        sendDatagramToOutput(fragment, ie, nextHopAddr, vforwarder);
    }

    delete datagram;
}
