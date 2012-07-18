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
 * Author: Qasim Javed <qasim@utdallas.edu>
 */
#ifndef NAT_RULE_H
#define NAT_RULE_H

#include "ns3/log.h"
#include "ns3/ipv4-address.h"
#include "ns3/ref-count-base.h"
#include "ns3/ptr.h"
#include "ns3/object.h"
#include "ns3/callback.h"
#include "ns3/net-device.h"
//#include "ipv4-interface.h"
//#include "jhash.h"


namespace ns3 {

class Object;
class Ipv4Address;
class NetDevice;

class NatRule : public RefCountBase {
  public:
    NatRule (Ipv4Address orig, Ipv4Address mapped, Ptr<NetDevice> device); //, Ipv4Interface outInterface);
    bool operator == (const NatRule& other) const;
    Ipv4Address GetOriginalSource () const;

    Ipv4Address GetMangledSource () const;
    Ptr <NetDevice> GetDevice () const;
  
  private:
    Ipv4Address m_originalSource;
    Ipv4Address m_mangledSource;
    Ptr <NetDevice> m_device;
    //Ipv4Interface m_outInterface;
};

}
#endif /* NAT_RULE_H */
