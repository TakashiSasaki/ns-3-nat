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
#include "ns3/output-stream-wrapper.h"
#include "ipv4-nat.h"

NS_LOG_COMPONENT_DEFINE ("Ipv4Nat");

namespace ns3 {

     
NS_OBJECT_ENSURE_REGISTERED (Ipv4Nat);

TypeId
Ipv4Nat::GetTypeId (void)
{
  static TypeId tId = TypeId ("ns3::Ipv4Nat")
    .SetParent<Object> ()
  ;

  return tId;
}


Ipv4Nat::Ipv4Nat ()

  {

  NS_LOG_FUNCTION (this);

  NetfilterHookCallback doNat = MakeCallback (&Ipv4Nat::NetfilterDoNat, this);
  NetfilterHookCallback doUnNat = MakeCallback (&Ipv4Nat::NetfilterDoUnNat, this);

  Ipv4NetfilterHook natCallback1 = Ipv4NetfilterHook (1, NF_INET_POST_ROUTING, NF_IP_PRI_NAT_SRC, doNat); 
  Ipv4NetfilterHook natCallback2 = Ipv4NetfilterHook (1, NF_INET_PRE_ROUTING, NF_IP_PRI_NAT_DST, doUnNat); 
  

#if 0
  // XXX this hook should be registered on the Netfilter object instead
  this->RegisterHook (natCallback1);
  this->RegisterHook (natCallback2);
#endif

  }

uint32_t 
Ipv4Nat::GetNStaticRules (void) const
  {
  NS_LOG_FUNCTION (this);
  return 0;
  }

uint32_t 
Ipv4Nat::GetNDynamicRules (void) const
  {
  NS_LOG_FUNCTION (this);
  return 0;
  }

void
Ipv4Nat::RemoveStaticRule (uint32_t index)
  {
  NS_LOG_FUNCTION (this << index);

  }

void
Ipv4Nat::RemoveDynamicRule (uint32_t index)
  {
  NS_LOG_FUNCTION (this << index);

  }


  /**
   * \brief Print the NAT translation table
   *
   * \param stream the ostream the NAT table is printed to
   */

/*void PrintTable (Ptr<OutputStreamWrapper> stream) const

  {
    NS_LOG_DEBUG("Print Tables");

  }
*/  
uint32_t
Ipv4Nat::NetfilterDoNat (Hooks_t hookNumber, Ptr<Packet> p, 
                             Ptr<NetDevice> in, Ptr<NetDevice> out, ContinueCallback& ccb)
  {
    NS_LOG_FUNCTION (this << hookNumber << in << out);
      return 0;

  }

uint32_t 
Ipv4Nat::NetfilterDoUnNat (Hooks_t hookNumber, Ptr<Packet> p, 
                             Ptr<NetDevice> in, Ptr<NetDevice> out, ContinueCallback& ccb)
  {
    NS_LOG_FUNCTION (this << hookNumber << in << out);
      return 0;

  }
 
void 
Ipv4Nat::AddAddressPool (Ipv4Address globalip, Ipv4Mask globalmask)
{
    NS_LOG_FUNCTION (this << globalip << globalmask);
}

  
void 
Ipv4Nat::AddPortPool (uint16_t strprt, uint16_t dstprt) //port range 
{
    NS_LOG_FUNCTION (this << strprt << dstprt);
}

void 
Ipv4Nat::SetInside (uint32_t interfaceIndex)
{
    NS_LOG_FUNCTION (this << interfaceIndex);

}
  
void 
Ipv4Nat::SetOutside (uint32_t interfaceIndex)
{
   
  NS_LOG_FUNCTION (this << interfaceIndex);
}


void 
Ipv4Nat::AddDynamicRule(const Ipv4DynamicNatRule&)
{
  NS_LOG_FUNCTION (this); 
}


void 
Ipv4Nat::AddStaticRule(const Ipv4StaticNatRule&)
{
  NS_LOG_FUNCTION (this);
}

Ipv4StaticNatRule::Ipv4StaticNatRule (Ipv4Address localip, uint16_t locprt, Ipv4Address globalip,uint16_t gloprt, uint16_t protocol)
    {
  NS_LOG_FUNCTION (this << localip << locprt << globalip << gloprt << protocol);
      m_localaddr = localip;
      m_globaladdr = globalip;
      m_localport = locprt;
      m_globalport = gloprt;
      //m_protocol = 0;
    }

     // This version is used for no port restrictions
Ipv4StaticNatRule::Ipv4StaticNatRule (Ipv4Address localip, Ipv4Address globalip)
      {
  NS_LOG_FUNCTION (this << localip << globalip);
        m_localaddr = localip;
        m_globaladdr = globalip;
      }


Ipv4DynamicNatRule::Ipv4DynamicNatRule (Ipv4Address localnet, Ipv4Mask localmask)
  {
  NS_LOG_FUNCTION (this << localnet << localmask);
    m_localnetwork = localnet;
    m_localmask = localmask;
  }
  
}
