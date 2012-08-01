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

  static TypeId GetTypeId (void);

  virtual ~Ipv4Nat ();

  /**
   * \brief Print the NAT translation table
   *
   * \param stream the ostream the NAT table is printed to
   */
  void AddRule (const Ipv4NatRule& natRule);

  /**
   * \return number of NAT rules
   */
  uint32_t GetNRules (void) const;

  /**
   * \param index index in table specifying rule to return
   * \return rule at specified index
   */
  Ipv4NatRule GetRule (uint32_t index) const;

  /**
   * \param index index in table specifying rule to remove
   */
  void RemoveRule (uint32_t index);

  /**
   * \brief Print the NAT translation table
   *
   * \param stream the ostream the NAT table is printed to
   */
  void PrintTable (Ptr<OutputStreamWrapper> stream) const;

  uint32_t NetfilterDoNat (Hooks_t hookNumber, Ptr<Packet> p, 
                             Ptr<NetDevice> in, Ptr<NetDevice> out, ContinueCallback& ccb);

  uint32_t NetfilterDoUnNat (Hooks_t hookNumber, Ptr<Packet> p, 
                             Ptr<NetDevice> in, Ptr<NetDevice> out, ContinueCallback& ccb);
  



};

}
