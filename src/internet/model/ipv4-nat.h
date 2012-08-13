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
#include "ipv4.h"


namespace ns3 {

class Packet;
class NetDevice;
class OutputStreamWrapper;

/**
  * \brief Implementation of the Static NAT Rule.
  *
  * This implements the basic static NAT rule structure with some
  * methods to access their attributes.
  */

class Ipv4StaticNatRule
{
public:
  Ipv4StaticNatRule (Ipv4Address localip, uint16_t locprt, Ipv4Address globalip,uint16_t gloprt, uint16_t protocol);

  // This version is used for no port restrictions
  Ipv4StaticNatRule (Ipv4Address localip, Ipv4Address globalip);

  Ipv4Address GetLocalIp () const;
  Ipv4Address GetGlobalIp () const;
  uint16_t GetLocalPort () const;
  uint16_t GetGlobalPort () const;
  uint16_t GetProtocol () const;


private:
  Ipv4Address m_localaddr;
  Ipv4Address m_globaladdr;
  uint16_t m_localport;
  uint16_t m_globalport;
  uint16_t m_protocol;

  // private data member
};


/**
  * \brief Implementation of the Static NAT Rule.
  *
  * This implements the basic static NAT rule structure with some
  * methods to access their attributes.
  */

class Ipv4DynamicNatRule
{
public:
  Ipv4DynamicNatRule (Ipv4Address localnet, Ipv4Mask localmask);

private:
  Ipv4Address m_localnetwork;
  Ipv4Mask m_localmask;
  // private data members
};

/**
  * \brief Implementation of Nat
  *
  * This implements NAT functionality over a Netfilter framework.
  * The NAT is of two major types (static and dynamic).
  */

class Ipv4Nat : public Object
{
public:
  static TypeId GetTypeId (void);

  Ipv4Nat ();

  /**
   * \brief Add rules to the NAT Tables.
   *
   * \param rule NAT rule reference reference to the NAT rule to be added
   *
   * Adds a NAT rule to the lists that have been dedicated for the specific types
   * of rules.
   */

  void AddDynamicRule (const Ipv4DynamicNatRule& rule);
  void AddStaticRule (const Ipv4StaticNatRule& rule);

  /**
   * \return number of NAT rules
   *
   * Returns the number of rules that are currently listed on the list.
   */
  uint32_t GetNStaticRules (void) const;
  uint32_t GetNDynamicRules (void) const;

  /**
   * \param index index in table specifying rule to return
   * \return rule at specified index
   *
   * Returns the specific Static NAT rule that is stored on the given index.
   */
  Ipv4StaticNatRule GetStaticRule (uint32_t index) const;

  /**
   * \param index index in table specifying rule to remove
   *
   * Removes the NAT rule that is stored on the given index.
   */
  void RemoveStaticRule (uint32_t index);
  void RemoveDynamicRule (uint32_t index);

  /**
   * \brief Print the NAT translation table
   *
   * \param stream the ostream the NAT table is printed to
   *
   * Prints out the NAT table.
   */
  void PrintTable (Ptr<OutputStreamWrapper> stream) const;

  /**
   * \brief Add the address pool for Dynamic NAT
   *
   * \param Ipv4address the addresses to be added in the Dynamic Nat pool
   * \param Ipv4Mask the mask of the pool of network address given
   */
  void AddAddressPool (Ipv4Address, Ipv4Mask);

  /**
   * \brief Add the port pool for Dynamic NAT
   *
   * \param     numbers for the port pool
   * \param port
   */
  void AddPortPool (uint16_t, uint16_t); //port range

  /**
   * \brief Set the specific interfaces for the node
   *
   * \param interfaceIndex interface index number of the interface on the node
   */
  void SetInside (int32_t interfaceIndex);
  void SetOutside (int32_t interfaceIndex);

  typedef std::list<Ipv4StaticNatRule> StaticNatRules;
  typedef std::list<Ipv4DynamicNatRule> DynamicNatRules;

protected:
  // from Object base class
  virtual void NotifyNewAggregate (void);

private:
  //bool m_isConnected;

  Ptr<Ipv4> m_ipv4;

  /**
    * \param hook The hook number e.g., NF_INET_PRE_ROUTING
    * \param p Packet that is handed over to the callback chain for this hook
    * \param in NetDevice which received the packet
    * \param out The outgoing NetDevice
    * \param ccb If not NULL, this callback will be invoked once the hook
    * callback chain has finished processing
    *
    * \returns Netfilter verdict for the Packet. e.g., NF_ACCEPT, NF_DROP etc.
    *
    *  This method is invoke to perform NAT of the packet at the NF_INET_PRE_ROUTING stage.
    */

  uint32_t DoNatPreRouting (Hooks_t hookNumber, Ptr<Packet> p,
                            Ptr<NetDevice> in, Ptr<NetDevice> out, ContinueCallback& ccb);

  /**
     * \param hook The hook number e.g., NF_INET_PRE_ROUTING
     * \param p Packet that is handed over to the callback chain for this hook
     * \param in NetDevice which received the packet
     * \param out The outgoing NetDevice
     * \param ccb If not NULL, this callback will be invoked once the hook
     * callback chain has finished processing
     *
     * \returns Netfilter verdict for the Packet. e.g., NF_ACCEPT, NF_DROP etc.
     *
     *  This method is invoke to perform NAT of the packet at the NF_INET_POST_ROUTING stage.
     */

  uint32_t DoNatPostRouting (Hooks_t hookNumber, Ptr<Packet> p,
                             Ptr<NetDevice> in, Ptr<NetDevice> out, ContinueCallback& ccb);

  StaticNatRules m_statictable;
  DynamicNatRules m_dynamictable;
  int32_t m_insideInterface;
  int32_t m_outsideInterface;

};

}
#endif

