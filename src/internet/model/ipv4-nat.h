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
#ifndef IPV4_NAT_H
#define IPV4_NAT_H

#include <stdint.h>
#include <limits.h>
#include <sys/socket.h>
#include "ns3/ptr.h"
#include "ns3/net-device.h"
#include "ns3/packet.h"
#include "ns3/ipv4-header.h"
#include "ns3/object.h"
#include "ipv4-netfilter.h"
#include "ipv4-netfilter-hook.h"
#include "netfilter-callback-chain.h"

#include "netfilter-tuple-hash.h"
#include "netfilter-conntrack-tuple.h"
#include "netfilter-conntrack-l3-protocol.h"
#include "netfilter-conntrack-l4-protocol.h"
#include "ip-conntrack-info.h"

namespace ns3 {

class Packet;
class NetDevice;
class OutputStreamWrapper;

class Ipv4StaticNatRule
{
public:
  Ipv4StaticNatRule (Ipv4Address localip, uint16_t locprt, Ipv4Address globalip,uint16_t gloprt, uint16_t protocol);

  // This version is used for no port restrictions
  Ipv4StaticNatRule (Ipv4Address localip, Ipv4Address globalip);

  Ipv4Address GetLocalIp();
  Ipv4Address GetGlobalIp();

private:
  Ipv4Address m_localaddr;
  Ipv4Address m_globaladdr;
  uint16_t m_localport;
  uint16_t m_globalport;

  // private data member
};


class Ipv4DynamicNatRule
{
public:
  Ipv4DynamicNatRule (Ipv4Address localnet, Ipv4Mask localmask);

private:
  Ipv4Address m_localnetwork;
  Ipv4Mask m_localmask;
  // private data members
};

class Ipv4Nat : public Object
{
public:
  static TypeId GetTypeId (void);

  Ipv4Nat ();

  /**
   * \brief Print the NAT translation table
   *
   * \param stream the ostream the NAT table is printed to
   */

  void AddDynamicRule (const Ipv4DynamicNatRule& rule);

  void AddStaticRule (const Ipv4StaticNatRule& rule);
  /**
   * \return number of NAT rules
   */
  uint32_t GetNStaticRules (void) const;

  uint32_t GetStaticRule (uint32_t index) const;

  uint32_t GetNDynamicRules (void) const;
  /**
   * \param index index in table specifying rule to return
   * \return rule at specified index
   */
  //Ipv4NatRule GetRule (uint32_t index) const;

  /**
   * \param index index in table specifying rule to remove
   */
  void RemoveStaticRule (uint32_t index);

  void RemoveDynamicRule (uint32_t index);
  /**
   * \brief Print the NAT translation table
   *
   * \param stream the ostream the NAT table is printed to
   */
  void PrintTable (Ptr<OutputStreamWrapper> stream) const;

  void AddAddressPool (Ipv4Address, Ipv4Mask);

  void AddPortPool (uint16_t, uint16_t); //port range

  void SetInside (uint32_t interfaceIndex);

  void SetOutside (uint32_t interfaceIndex);

  typedef std::list<Ipv4StaticNatRule> StaticNatRules;
  typedef std::list<Ipv4DynamicNatRule> DynamicNatRules;

protected:
  // from Object base class
  virtual void NotifyNewAggregate (void);

private:
  bool m_isConnected;
  uint32_t NetfilterDoNat (Hooks_t hookNumber, Ptr<Packet> p,
                           Ptr<NetDevice> in, Ptr<NetDevice> out, ContinueCallback& ccb);

  uint32_t NetfilterDoUnNat (Hooks_t hookNumber, Ptr<Packet> p,
                             Ptr<NetDevice> in, Ptr<NetDevice> out, ContinueCallback& ccb);

  StaticNatRules m_statictable;
  DynamicNatRules m_dynamictable;

};

}
#endif

