//
// Copyright (C) 2011 CoCo Communications
// Copyright (C) 2012 Opensim Ltd
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program; if not, see <http://www.gnu.org/licenses/>.
//

class noncobject IPv4Address;

cplusplus {{
#include "INETDefs.h"
#include "IPv4Address.h"
#include <vector>
typedef std::vector<IPv4Address> IPVector;
}}

class noncobject IPVector;

enum IGMPType
{
    IGMP_MEMBERSHIP_QUERY = 0x11;
    IGMPV1_MEMBERSHIP_REPORT = 0x12;
    IGMPV2_MEMBERSHIP_REPORT = 0x16;
    IGMPV2_LEAVE_GROUP = 0x17;
	IGMPV3_MEMBERSHIP_REPORT = 0x22;
}

struct GroupRecord
{
    int recordType;
    int numOfSources;
    IPv4Address groupAddress;
    IPVector SourceList;
};

packet IGMPMessage
{
    int type enum(IGMPType);
    int maxRespTime;
    IPv4Address groupAddress;
}

packet IGMPv3Query
{
    int type enum(IGMPType) = IGMP_MEMBERSHIP_QUERY;
    int maxRespCode;
    IPv4Address groupAddress;
    int numOfSources;
    IPVector sourceList;
}

packet IGMPv3Report
{
    int type enum(IGMPType) = IGMPV3_MEMBERSHIP_REPORT;
    int numGroupRecords;
    GroupRecord groupRecord[];
}
