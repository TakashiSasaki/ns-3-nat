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

  class Packet;
  class NetDevice;
     
class Ipv4Nat  : public Object
{
public:

  static TypeId GetTypeId (void);

  Ipv4Nat :: Ipv4Nat ()
  {

  NS_LOG_DEBUG (":: Enabling NAT ::");

  NetfilterHookCallback doNat = MakeCallback (&Ipv4Netfilter::NetfilterDoNat, this);
  NetfilterHookCallback doUnNat = MakeCallback (&Ipv4Netfilter::NetfilterDoUnNat, this);

  Ipv4NetfilterHook natCallback1 = Ipv4NetfilterHook (1, NF_INET_POST_ROUTING, NF_IP_PRI_NAT_SRC, doNat); 
  Ipv4NetfilterHook natCallback2 = Ipv4NetfilterHook (1, NF_INET_PRE_ROUTING, NF_IP_PRI_NAT_DST, doUnNat); 
  

  this->RegisterHook (natCallback1);
  this->RegisterHook (natCallback2);

  }

  /**
   * \brief Print the NAT translation table
   *
   * \param stream the ostream the NAT table is printed to
   */
  void AddRule (const Ipv4NatRule& natRule)
  {
  NS_LOG_DEBUG("Add Rules");
  }


  /**
   * \return number of NAT rules
   */
  uint32_t GetNRules (void) const
  {
  NS_LOG_DEBUG("Get N Rules");
  return 0;
  }


  /**
   * \param index index in table specifying rule to return
   * \return rule at specified index
   */
  Ipv4NatRule GetRule (uint32_t index) const
  {

  NS_LOG_DEBUG("Print Tables");
  
  }


  /**
   * \param index index in table specifying rule to remove
   */
  void RemoveRule (uint32_t index)
  {
       NS_LOG_DEBUG("Remove Rules");

  }


  /**
   * \brief Print the NAT translation table
   *
   * \param stream the ostream the NAT table is printed to
   */
  void PrintTable (Ptr<OutputStreamWrapper> stream) const

  {
    NS_LOG_DEBUG("Print Tables");

  }

  uint32_t NetfilterDoNat (Hooks_t hookNumber, Ptr<Packet> p, 
                             Ptr<NetDevice> in, Ptr<NetDevice> out, ContinueCallback& ccb)
  {
      NS_LOG_DEBUG("Nat Callback1");
      return 0;

  }

  uint32_t NetfilterDoUnNat (Hooks_t hookNumber, Ptr<Packet> p, 
                             Ptr<NetDevice> in, Ptr<NetDevice> out, ContinueCallback& ccb)
  {
      NS_LOG_DEBUG("UnNat Callback");
      return 0;

  }



};

}
