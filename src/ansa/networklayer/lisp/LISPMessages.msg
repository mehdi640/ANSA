//
// Copyright (C) 2013 Brno University of Technology
// Copyright (C) 2010 Michael Hoefling
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
// 

cplusplus {{
#include "INETDefs.h"
#include "IPAddress.h"

struct recordsPtr;
struct locator;

class noncobject IPAddress;

packet LISPHeader {
    string displayString = "b=15,15,oval,blue,black,2"; // for demo purposes only
    bool Nbit; 											// nonce-present bit
    bool Lbit; 											// locator-status-bits field enabled
    bool Ebit; 											// echo-nonce-request bit
    bool Vbit; 											// map-version persent bit
    bool Ibit; 											// instance id bit
    char flags;
    unsigned int nonce; 								// nonce
    unsigned int mapVersion; 							// map-version
    unsigned int instanceId; 							// instanceId
    unsigned int locatorStatusBits; 					// locator-status-bits field
}

packet LISPMessage {
    string displayString;
    char type				//message type
    bool pbit; 				// probe bit
    unsigned int nonce; 	// nonce
}

packet LISPMapReply extends LISPMessage {
    string displayString = "b=15,15,oval,green,black,2";
    IPAddress eidPrefix[]; // eid-prefix
    unsigned int eidPrefixLength[]; // eid-prefix length
    unsigned int mapVersion[]; // map-version
    bool abit[]; // authoritative bit
    recordsPtr records[]; // list of locators
    bool locatorTypeBit[];
    simtime_t recordTTL; //TTL
    // Missing:
    // Detailed record information
    // Mapping Protocol Data
    // Echo-Nonce locator reachability algorithm
    // Multiple EIDs in one reply
}

packet LISPMapRequest extends LISPMessage {
    string displayString = "b=15,15,oval,red,black,2";
    type = 0;
    bool Abit;						// Authoritative bit 
    bool Mbit;						// Map-data-present bit
    bool Pbit;						// Probe bit
    bool Sbit;						// Solicit-Map-Request bit
    bool pbit;						// PITR bit
    bool sbit;						// SMR-invoked bit
    unsigned char itrRlocCount;		// number of itrRlocs
    unsigned char recordCount;		// number of records    
    IPAddress itrRlocs[]; 			// addresses of itr used to send map-reply to
    unsigned int eidPrefixLength[]; // list of eid-prefix lengths
    unsigned char eidPrefixAFI[];	// list of eid-prefix AFIs 
    IPAddress eidPrefix[]; 			// list of eid-prefixes
    
    LISPMapReply mapReply; //Map-Reply Record
}

packet LISPMapRegister extends LISPMessage {
    string displayString = "b=15,15,oval,yellow,black,2";
    IPAddress eidPrefix[]; // list of eid-prefixes
    unsigned int eidPrefixLength[]; // list of eid-prefix lengths
    unsigned int mapVersion[]; // map-version
    recordsPtr records[]; // list of list of locators
    bool locatorTypeBit[];
    bool Mbit; // map-notify
    bool Pbit; //piggy_advanced
    bool Nbit; //NTR mechanism
    simtime_t recordTTL; //TTL
    // Missing:
    // Security
}

packet LISPMapNotify extends LISPMessage {
    string displayString = "b=15,15,oval,orange,black,2";
    IPAddress eidPrefix[]; // list of eid-prefixes
    unsigned int eidPrefixLength[]; // list of eid-prefix lengths
    unsigned int mapVersion[]; // map-version
    recordsPtr records[]; // list of list of locators
    bool locatorTypeBit[];
    bool Mbit; // map-notify
    // Missing:
    // Security
}
