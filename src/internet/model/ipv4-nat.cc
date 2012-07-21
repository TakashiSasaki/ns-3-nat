/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2009 University of Texas at Dallas
 *
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
#include "ns3/log.h"
#include "ns3/uinteger.h"
#include "ipv4-netfilter.h"

#include "ip-conntrack-info.h"
#include "ipv4-conntrack-l3-protocol.h"
#include "tcp-conntrack-l4-protocol.h"
#include "udp-conntrack-l4-protocol.h"
#include "icmpv4-conntrack-l4-protocol.h"

#include "tcp-header.h"
#include "udp-header.h"
#include "ns3/node.h"
#include "ns3/net-device.h"

NS_LOG_COMPONENT_DEFINE ("Ipv4Nat");

namespace ns3 {

NS_OBJECT_ENSURE_REGISTERED (Ipv4Nat);

Ipv4Netfilter::Ipv4Netfilter ()
{
  NS_LOG_DEBUG (":: Enabling NAT ::");

  NetfilterHookCallback doNat = MakeCallback (&Ipv4Netfilter::NetfilterDoNat, this);

  Ipv4NetfilterHook natCallback1 = Ipv4NetfilterHook (1, NF_INET_POST_ROUTING, NF_IP_PRI_NAT_SRC, doNat);
  Ipv4NetfilterHook natCallback2 = Ipv4NetfilterHook (1, NF_INET_PRE_ROUTING, NF_IP_PRI_NAT_DST, doNat);


  this->RegisterHook (natCallback1);
  this->RegisterHook (natCallback2);

}

  
uint32_t
Ipv4Netfilter::NetfilterDoNat (Hooks_t hookNumber, Ptr<Packet> p,
                               Ptr<NetDevice> in, Ptr<NetDevice> out, ContinueCallback& ccb)
{
  
    NS_LOG_UNCOND("NAT CALLBACK");

    return 0;
}


void
Ipv4Netfilter::AddNatRule (NatRule natRule)
{
  NS_LOG_UNCOND("NAT");
}

/*
std::vector<NatRule>::iterator
Ipv4Netfilter::FindNatRule (NatRule natRule)
{
  std::vector<NatRule>::iterator it = m_natRules.begin ();

  for (; it != m_natRules.end ();  it++)
    {
      if ( *it == natRule )
        {
          return it;
        }
    }

  return m_natRules.end ();
}

std::vector<NatRule>::iterator
Ipv4Netfilter::FindNatRule (Ipv4Address orig, Ptr<NetDevice> out)
{
  std::vector<NatRule>::iterator it = m_natRules.begin ();

  NS_LOG_DEBUG ("Number of rules: " << m_natRules.size () );
  NS_LOG_DEBUG ("Orig: " << orig );

  for (; it != m_natRules.end ();  it++)
    {
      NS_LOG_DEBUG ("Rule source: " << it->GetOriginalSource () << ", passed in source: " << orig);
      NS_LOG_DEBUG ("Rule device: " << it->GetDevice () << ", passed in dev: " << out);
      if ( it->GetOriginalSource () == orig && it->GetDevice () == out)
        {
          NS_LOG_DEBUG ("Rule match found!");
          return it;
        }
    }

  return m_natRules.end ();
}
*/


uint32_t
Ipv4Netfilter::NetfilterNatPacket (Hooks_t hookNumber, Ptr<Packet> p)
{
  NS_LOG_UNCOND("NAT");
  return 0;
}
}
