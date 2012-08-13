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

Ipv4Nat::Ipv4Nat ()
  : m_insideInterface (-1),
    m_outsideInterface (-1)
{
  NS_LOG_FUNCTION (this);

  NetfilterHookCallback doNatPreRouting = MakeCallback (&Ipv4Nat::DoNatPreRouting, this);
  NetfilterHookCallback doNatPostRouting = MakeCallback (&Ipv4Nat::DoNatPostRouting, this);

  natCallback1 = Ipv4NetfilterHook (1, NF_INET_POST_ROUTING, NF_IP_PRI_NAT_SRC, doNatPostRouting);
  natCallback2 = Ipv4NetfilterHook (1, NF_INET_PRE_ROUTING, NF_IP_PRI_NAT_DST, doNatPreRouting);

}

/*
 * This method is called by AddAgregate and completes the aggregation
 * by hooking to the Ipv4Netfilter
 */
void
Ipv4Nat::NotifyNewAggregate ()
{
  NS_LOG_FUNCTION (this);
  if (m_ipv4 != 0)
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
              m_ipv4 = ipv4;
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

void
Ipv4Nat::RemoveStaticRule (uint32_t index)
{

  NS_LOG_FUNCTION (this << index);
  NS_ASSERT (index < m_statictable.size ());
  uint32_t tmp = 0;
  for (StaticNatRules::iterator i = m_statictable.begin ();
       i != m_statictable.end (); i++, tmp++)
    {
      if (tmp == index)
        {
          m_statictable.erase (i);
          return;
        }
    }
  NS_ASSERT_MSG (false, "Rule Not Found");
}

void
Ipv4Nat::RemoveDynamicRule (uint32_t index)
{
  NS_LOG_FUNCTION (this << index);
  return;
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
      *os << "Local IP     Local Port     Global IP    Global Port " << std::endl;
      for (uint32_t i = 0; i < GetNStaticRules (); i++)
        {
          std::ostringstream locip,gloip,locprt,gloprt;
          Ipv4StaticNatRule rule = GetStaticRule (i);

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
Ipv4Nat::DoNatPreRouting (Hooks_t hookNumber, Ptr<Packet> p,
                          Ptr<NetDevice> in, Ptr<NetDevice> out, ContinueCallback& ccb)
{
  NS_LOG_FUNCTION (this << p << hookNumber << in << out);

  if (m_ipv4 == 0)
    {
      return 0;
    }

  Ipv4Header ipHeader;

  NS_LOG_DEBUG ("Input device " << m_ipv4->GetInterfaceForDevice (in) << " inside interface " << m_insideInterface);
  NS_LOG_DEBUG ("Output device " << m_ipv4->GetInterfaceForDevice (out) << " outside interface " << m_outsideInterface);
  // XXX consider PeekHeader here
  p->RemoveHeader (ipHeader);
  if (m_ipv4->GetInterfaceForDevice (in) == m_insideInterface)
    {
      // inside interface is the input interface, NAT the source addr
      NS_LOG_DEBUG ("evaluating packet with src " << ipHeader.GetSource () << " dst " << ipHeader.GetDestination ());
      Ipv4Address srcAddress = ipHeader.GetSource ();

      for (StaticNatRules::const_iterator i = m_statictable.begin ();
           i != m_statictable.end (); i++)
        {
          if (srcAddress == (*i).GetLocalIp ())
            {
              NS_LOG_DEBUG ("Rule match");
              ipHeader.SetSource ((*i).GetGlobalIp ());

              if ((*i).GetProtocol () == 0)
                {
                  break;
                }

              else
                {
                  NS_LOG_DEBUG ("evaluating rule with local port " << (*i).GetLocalPort () << " global port " << (*i).GetGlobalPort ());

                  if (ipHeader.GetProtocol () == IPPROTO_TCP && (*i).GetProtocol () == IPPROTO_TCP)

                    {
                      TcpHeader tcpHeader;

                      p->RemoveHeader (tcpHeader);

                      if (tcpHeader.GetSourcePort () == (*i).GetLocalPort ())
                        {

                          tcpHeader.SetSourcePort ((*i).GetGlobalPort ());
                        }

                      p->AddHeader (tcpHeader);

                    }
                  else
                  if (ipHeader.GetProtocol () == IPPROTO_UDP && (*i).GetProtocol () == IPPROTO_UDP)
                    {
                      UdpHeader udpHeader;

                      p->RemoveHeader (udpHeader);

                      if (udpHeader.GetSourcePort () == (*i).GetLocalPort ())
                        {
                          udpHeader.SetSourcePort ((*i).GetGlobalPort ());
                        }

                      p->AddHeader (udpHeader);
                    }

                }

              break;


            }
        }
    }
  if (m_ipv4->GetInterfaceForDevice (in) == m_outsideInterface)
    {
      // outside interface is the input interface, NAT the destination addr
      NS_LOG_DEBUG ("evaluating packet with src " << ipHeader.GetSource () << " dst " << ipHeader.GetDestination ());
      Ipv4Address destAddress = ipHeader.GetDestination ();

      for (StaticNatRules::const_iterator i = m_statictable.begin ();
           i != m_statictable.end (); i++)
        {
          if (destAddress == (*i).GetGlobalIp ())
            {
              NS_LOG_DEBUG ("Rule match");
              ipHeader.SetDestination ((*i).GetLocalIp ());

              if ((*i).GetProtocol () == 0)
                {
                  break;
                }

              else
                {
                  NS_LOG_DEBUG ("evaluating rule with local port " << (*i).GetLocalPort () << " global port " << (*i).GetGlobalPort ());

                  if (ipHeader.GetProtocol () == IPPROTO_TCP && (*i).GetProtocol () == IPPROTO_TCP)

                    {
                      TcpHeader tcpHeader;

                      p->RemoveHeader (tcpHeader);

                      if (tcpHeader.GetDestinationPort () == (*i).GetGlobalPort ())
                        {

                          tcpHeader.SetDestinationPort ((*i).GetLocalPort ());
                        }

                      p->AddHeader (tcpHeader);

                    }
                  else
                  if (ipHeader.GetProtocol () == IPPROTO_UDP && (*i).GetProtocol () == IPPROTO_UDP)
                    {
                      UdpHeader udpHeader;

                      p->RemoveHeader (udpHeader);

                      if (udpHeader.GetDestinationPort () == (*i).GetGlobalPort ())
                        {
                          udpHeader.SetDestinationPort ((*i).GetLocalPort ());
                        }

                      p->AddHeader (udpHeader);
                    }

                }

              break;


            }
        }
    }
  p->AddHeader (ipHeader);

  return 0;
}

uint32_t
Ipv4Nat::DoNatPostRouting (Hooks_t hookNumber, Ptr<Packet> p,
                           Ptr<NetDevice> in, Ptr<NetDevice> out, ContinueCallback& ccb)
{
  NS_LOG_FUNCTION (this << p << hookNumber << in << out);

  if (m_ipv4 == 0)
    {
      return 0;
    }

  Ipv4Header ipHeader;

  NS_LOG_DEBUG ("Input device " << m_ipv4->GetInterfaceForDevice (in) << " inside interface " << m_insideInterface);
  NS_LOG_DEBUG ("Output device " << m_ipv4->GetInterfaceForDevice (out) << " outside interface " << m_outsideInterface);
  // XXX consider PeekHeader here
  p->RemoveHeader (ipHeader);
  if (m_ipv4->GetInterfaceForDevice (out) == m_outsideInterface)
    {
      // matching output interface
      NS_LOG_DEBUG ("evaluating packet with src " << ipHeader.GetSource () << " dst " << ipHeader.GetDestination ());

      Ipv4Address srcAddress = ipHeader.GetSource ();

      for (StaticNatRules::const_iterator i = m_statictable.begin ();
           i != m_statictable.end ();
           i++)
        {
          NS_LOG_DEBUG ("Evaluating rule with local " << (*i).GetLocalIp () << " global " << (*i).GetGlobalIp ());
          if (srcAddress == (*i).GetLocalIp ())
            {
              NS_LOG_DEBUG ("Rule match");
              ipHeader.SetSource ((*i).GetGlobalIp ());

              if ((*i).GetProtocol () == 0)
                {
                  break;
                }

              else
                {
                  NS_LOG_DEBUG ("evaluating rule with local port " << (*i).GetLocalPort () << " global " << (*i).GetGlobalPort ());

                  if (ipHeader.GetProtocol () == IPPROTO_TCP && (*i).GetProtocol () == IPPROTO_TCP)

                    {
                      TcpHeader tcpHeader;

                      p->RemoveHeader (tcpHeader);

                      if (tcpHeader.GetSourcePort () == (*i).GetLocalPort ())
                        {

                          tcpHeader.SetSourcePort ((*i).GetGlobalPort ());
                        }

                      p->AddHeader (tcpHeader);

                    }
                  else
                  if (ipHeader.GetProtocol () == IPPROTO_UDP && (*i).GetProtocol () == IPPROTO_UDP)
                    {
                      UdpHeader udpHeader;

                      p->RemoveHeader (udpHeader);

                      if (udpHeader.GetSourcePort () == (*i).GetLocalPort ())
                        {
                          udpHeader.SetSourcePort ((*i).GetGlobalPort ());
                        }

                      p->AddHeader (udpHeader);
                    }

                }

              break;
            }

        }
    }
  p->AddHeader (ipHeader);

  return 0;
}

void
Ipv4Nat::AddAddressPool (Ipv4Address globalip, Ipv4Mask globalmask)
{
  NS_LOG_FUNCTION (this << globalip << globalmask);
}


void
Ipv4Nat::AddPortPool (uint16_t strprt, uint16_t dstprt)     //port range
{
  NS_LOG_FUNCTION (this << strprt << dstprt);
}

void
Ipv4Nat::SetInside (int32_t interfaceIndex)
{
  NS_LOG_FUNCTION (this << interfaceIndex);
  m_insideInterface = interfaceIndex;

}

void
Ipv4Nat::SetOutside (int32_t interfaceIndex)
{

  NS_LOG_FUNCTION (this << interfaceIndex);
  m_outsideInterface = interfaceIndex;
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
  m_statictable.push_front (rule);
  NS_LOG_DEBUG ("list has " << m_statictable.size () << " elements after pushing");
  NS_ASSERT_MSG (m_ipv4, "Forgot to aggregate Ipv4Nat to Node");
  if (m_ipv4->GetInterfaceForAddress (rule.GetGlobalIp ()) != -1)
    {
      NS_LOG_WARN ("Adding node's own IP address as the global NAT address");
      return;
    }
  NS_ASSERT_MSG (m_outsideInterface > -1, "Forgot to assign outside interface");
  // Add address to outside interface so that node will proxy ARP for it
  Ipv4Mask outsideMask = m_ipv4->GetAddress (m_outsideInterface, 0).GetMask ();
  Ipv4InterfaceAddress natAddress (rule.GetGlobalIp (), outsideMask);
  m_ipv4->AddAddress (m_outsideInterface, natAddress);
}

Ipv4StaticNatRule::Ipv4StaticNatRule (Ipv4Address localip, uint16_t locprt, Ipv4Address globalip,uint16_t gloprt, uint16_t protocol)
{
  NS_LOG_FUNCTION (this << localip << locprt << globalip << gloprt << protocol);
  m_localaddr = localip;
  m_globaladdr = globalip;
  m_localport = locprt;
  m_globalport = gloprt;
  NS_ASSERT (protocol == 0 || protocol == IPPROTO_TCP || protocol == IPPROTO_UDP);
  m_protocol = protocol;

}

// This version is used for no port restrictions
Ipv4StaticNatRule::Ipv4StaticNatRule (Ipv4Address localip, Ipv4Address globalip)
{
  NS_LOG_FUNCTION (this << localip << globalip);
  m_localaddr = localip;
  m_globaladdr = globalip;
  m_localport = 0;
  m_globalport = 0;
  m_protocol = 0;
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

uint16_t
Ipv4StaticNatRule::GetProtocol () const
{
  return m_protocol;
}

Ipv4DynamicNatRule::Ipv4DynamicNatRule (Ipv4Address localnet, Ipv4Mask localmask)
{
  NS_LOG_FUNCTION (this << localnet << localmask);
  m_localnetwork = localnet;
  m_localmask = localmask;

}

}
