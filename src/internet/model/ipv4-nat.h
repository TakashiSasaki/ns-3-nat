/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <stdint.h>
#include <limits.h>
#include <sys/socket.h>
#include "ns3/ptr.h"
#include "ns3/net-device.h"
#include "ns3/packet.h"
#include "ns3/ipv4-header.h"
#include "ns3/object.h"

#include "ipv4-netfilter-hook.h"
#include "netfilter-callback-chain.h"

#include "netfilter-tuple-hash.h"
#include "netfilter-conntrack-tuple.h"
#include "netfilter-conntrack-l3-protocol.h"
#include "netfilter-conntrack-l4-protocol.h"
#include "ip-conntrack-info.h"
#include "nat-rule.h"

namespace ns3 {

  class Packet;
  class NetDevice;
  
  
class Ipv4Nat  : public Object
  {
    public:
  void AddNatRule (NatRule natRule);

  uint32_t NetfilterDoNat (Hooks_t hookNumber, Ptr<Packet> p,
                           Ptr<NetDevice> in, Ptr<NetDevice> out, ContinueCallback& ccb);


 // std::vector<NatRule>::iterator FindNatRule (NatRule natRule);

//  std::vector<NatRule>::iterator FindNatRule (Ipv4Address orig, Ptr<NetDevice> out);
  //static NetfilterConntrackTuple currentTuple[IP_CT_DIR_MAX];

//  void EnableNat ();

  uint32_t NetfilterNatPacket (Hooks_t hookNumber, Ptr<Packet> p);



    private:

        TranslationMap m_natReplyLookup;
        std::vector <NatRule> m_natRules;
  };
}
