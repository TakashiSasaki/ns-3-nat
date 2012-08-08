/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
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
#include "ipv4.h"

#include <iomanip>

NS_LOG_COMPONENT_DEFINE ("Ipv4Nat");

namespace ns3 {

Ipv4NetfilterHook natCallback1;
Ipv4NetfilterHook natCallback2;

NS_OBJECT_ENSURE_REGISTERED (Ipv4Nat);

TypeId
Ipv4Nat::GetTypeId (void)
{
  static TypeId tId = TypeId ("ns3::Ipv4Nat")
    .SetParent<Object> ()
  ;

  return tId;
}


Ipv4Nat::Ipv4Nat () : m_isConnected (false)
{
  NS_LOG_FUNCTION (this);

  NetfilterHookCallback doNat = MakeCallback (&Ipv4Nat::NetfilterDoNat, this);
  NetfilterHookCallback doUnNat = MakeCallback (&Ipv4Nat::NetfilterDoUnNat, this);

  natCallback1 = Ipv4NetfilterHook (1, NF_INET_POST_ROUTING, NF_IP_PRI_NAT_SRC, doNat);
  natCallback2 = Ipv4NetfilterHook (1, NF_INET_PRE_ROUTING, NF_IP_PRI_NAT_DST, doUnNat);


}

/*
 * This method is called by AddAgregate and completes the aggregation
 * by hooking to the Ipv4Netfilter
 */
void
Ipv4Nat::NotifyNewAggregate ()
{
  NS_LOG_FUNCTION (this);
  if (m_isConnected)
    {
      return;
    }
  Ptr<Node> node = this->GetObject<Node> ();
  if (node != 0)
    {
      Ptr<Ipv4> ipv4 = node->GetObject<Ipv4> ();
      if (ipv4 != 0)
        {
          Ptr<Ipv4Netfilter> netfilter = ipv4->GetNetfilter ();
          if (ipv4 != 0)
            {
              m_isConnected = true;
              // Set callbacks on netfilter pointer

              netfilter->RegisterHook (natCallback1);
              netfilter->RegisterHook (natCallback2);

            }
        }
    }
  Object::NotifyNewAggregate ();
}

uint32_t
Ipv4Nat::GetNStaticRules (void) const
{
  NS_LOG_FUNCTION (this);
  return m_statictable.size ();
}

Ipv4StaticNatRule
Ipv4Nat::GetStaticRule (uint32_t index) const
{
  NS_LOG_FUNCTION (this << index);
  uint32_t tmp = 0;
  for (StaticNatRules::const_iterator i = m_statictable.begin ();
       i != m_statictable.end ();
       i++)
    {
      if (tmp == index)
        {
          return *i;
        }
      tmp++;
    }
  NS_ASSERT (false);

  return Ipv4StaticNatRule (Ipv4Address (), Ipv4Address ());
}



uint32_t
Ipv4Nat::GetNDynamicRules (void) const
{
  NS_LOG_FUNCTION (this);
  return 0;
}

uint32_t
Ipv4Nat::RemoveStaticRule (uint32_t index)
{

  NS_LOG_FUNCTION (this << index);
  uint32_t tmp = 0;
  for (StaticNatRules::const_iterator i = m_statictable.begin ();
       i != m_statictable.end ();
       i++)
    {
      if (tmp == index)
        {
          delete i->first;
          m_statictable.erase (i);
          return;
        }
      tmp++;
    }
  NS_ASSERT (false);

  return 0;

}

uint32_t
Ipv4Nat::RemoveDynamicRule (uint32_t index)
{
  NS_LOG_FUNCTION (this << index);
  return 0;
}


/**
 * \brief Print the NAT translation table
 *
 * \param stream the ostream the NAT table is printed to
 */

void
Ipv4Nat::PrintTable (Ptr<OutputStreamWrapper> stream) const

{
  NS_LOG_FUNCTION (this);
  std::ostream* os = stream->GetStream ();
  if (GetNStaticRules () > 0)
    {
      std::cout << "Inside PrintTable" << std::endl;
      *os << "Local IP     Local Port     Global IP    Global Port " << std::endl;
      for (uint32_t i = 0; i < GetNStaticRules (); i++)
        {
          std::ostringstream locip,gloip,locprt,gloprt;
          Ipv4StaticNatRule rule = GetStaticRule (i);
/*          locip << rule.GetLocalIp ();
          *os << std::setiosflags (std::ios::left) << std::setw (16) << locip.str ();
*/
          if (rule.GetLocalPort ())
            {
              locip << rule.GetLocalIp ();
              *os << std::setiosflags (std::ios::left) << std::setw (16) << locip.str ();

              locprt << rule.GetLocalPort ();
              *os << std::setiosflags (std::ios::left) << std::setw (16) << locprt.str ();
            }

          else
            {
              locip << rule.GetLocalIp ();
              *os << std::setiosflags (std::ios::left) << std::setw (35) << locip.str ();
            }


          gloip << rule.GetGlobalIp ();
          *os << std::setiosflags (std::ios::left) << std::setw (16) << gloip.str ();

          if (rule.GetGlobalPort ())
            {
              gloprt << rule.GetGlobalPort ();
              *os << std::setiosflags (std::ios::left) << std::setw (16) << gloprt.str ();
            }

          *os << std::endl;

        }
    }

}


uint32_t
Ipv4Nat::NetfilterDoNat (Hooks_t hookNumber, Ptr<Packet> p,
                         Ptr<NetDevice> in, Ptr<NetDevice> out, ContinueCallback& ccb)
{
  NS_LOG_FUNCTION (this << p << hookNumber << in << out);
  NS_LOG_UNCOND ("NAT Hook");

#if 0
  Ipv4Header ipHeader;
  Ipv4Address dstAddress, srcAddress;

  //Remove the header
  p->RemoveHeader (ipHeader);

  //Check the source ip of the pkt
  srcAddress = ipHeader.GetSource ();

  //iterate through the static rules list to find the first match for the src against the local ip

  for (StaticNatRules::const_iterator i = m_statictable.end ();
       i != m_statictable.begin ();
       i--)
    {
      if ( srcAddress == m_statictable.first)
        {
          //Set Source to the global ip of this matching rule
          ipHeader.SetSource = m_statictable.second;

        }
    }
  NS_ASSERT (false);
  return Ipv4StaticNatRule (Ipv4Address (), Ipv4Address ());

  //Reattach header

#endif

  return 0;

}

uint32_t
Ipv4Nat::NetfilterDoUnNat (Hooks_t hookNumber, Ptr<Packet> p,
                           Ptr<NetDevice> in, Ptr<NetDevice> out, ContinueCallback& ccb)
{
  NS_LOG_FUNCTION (this << hookNumber << in << out);

  //Remove the header

  //Check the source ip of the pkt

  //iterate through the static rules list to find the first match for the src against the local ip

  //Set Source to the global ip of this matching rule

  //Reattach header

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
Ipv4Nat::AddDynamicRule (const Ipv4DynamicNatRule&)
{
  NS_LOG_FUNCTION (this);
}


void
Ipv4Nat::AddStaticRule (const Ipv4StaticNatRule& rule)
{
  NS_LOG_FUNCTION (this);

  std::cout << "list has " << m_statictable.size () << " elements" << std::endl;
  m_statictable.push_front (rule);
  std::cout << "list has " << m_statictable.size () << " elements" << std::endl;
}

Ipv4StaticNatRule::Ipv4StaticNatRule (Ipv4Address localip, uint16_t locprt, Ipv4Address globalip,uint16_t gloprt, uint16_t protocol)
{
  NS_LOG_FUNCTION (this << localip << locprt << globalip << gloprt << protocol);
  m_localaddr = localip;
  m_globaladdr = globalip;
  m_localport = locprt;
  m_globalport = gloprt;
}

// This version is used for no port restrictions
Ipv4StaticNatRule::Ipv4StaticNatRule (Ipv4Address localip, Ipv4Address globalip)
{
  NS_LOG_FUNCTION (this << localip << globalip);
  m_localaddr = localip;
  m_globaladdr = globalip;
  m_localport = 0;
  m_globalport = 0;
}

Ipv4Address
Ipv4StaticNatRule::GetLocalIp () const
{
  return m_localaddr;
}

Ipv4Address
Ipv4StaticNatRule::GetGlobalIp () const
{
  return m_globaladdr;
}

uint16_t
Ipv4StaticNatRule::GetLocalPort () const
{
  return m_localport;
}

uint16_t
Ipv4StaticNatRule::GetGlobalPort () const
{
  return m_globalport;
}


Ipv4DynamicNatRule::Ipv4DynamicNatRule (Ipv4Address localnet, Ipv4Mask localmask)
{
  NS_LOG_FUNCTION (this << localnet << localmask);
  m_localnetwork = localnet;
  m_localmask = localmask;

}

}
