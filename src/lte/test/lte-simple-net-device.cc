/* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2011 Centre Tecnologic de Telecomunicacions de Catalunya (CTTC)
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
 * Author: Manuel Requena <manuel.requena@cttc.es>
 */

#include "ns3/simulator.h"
#include "ns3/pointer.h"
#include "ns3/log.h"
#include "ns3/lte-simple-net-device.h"

NS_LOG_COMPONENT_DEFINE ("LteSimpleNetDevice");

namespace ns3 {


NS_OBJECT_ENSURE_REGISTERED (LteSimpleNetDevice);


TypeId LteSimpleNetDevice::GetTypeId (void)
{
  static TypeId
    tid =
    TypeId ("ns3::LteSimpleNetDevice")
    .SetParent<SimpleNetDevice> ()
    .AddAttribute ("LteRlc",
                   "The RLC instance",
                   PointerValue (),
                   MakePointerAccessor (&LteSimpleNetDevice::m_rlc),
                   MakePointerChecker <LteRlc> ())
  ;

  return tid;
}


LteSimpleNetDevice::LteSimpleNetDevice (void)
{
  NS_LOG_FUNCTION (this);
  NS_FATAL_ERROR ("This constructor should not be called");
}


LteSimpleNetDevice::LteSimpleNetDevice (Ptr<Node> node, Ptr<LteRlc> rlc)
{
  NS_LOG_FUNCTION (this);
  m_rlc = rlc;
  SetNode (node);
}

LteSimpleNetDevice::~LteSimpleNetDevice (void)
{
  NS_LOG_FUNCTION (this);
}

void
LteSimpleNetDevice::DoDispose (void)
{
  NS_LOG_FUNCTION (this);
  m_rlc->Dispose ();
  m_rlc = 0;
  SimpleNetDevice::DoDispose ();
}


void
LteSimpleNetDevice::DoStart (void)
{
  NS_LOG_FUNCTION (this);
  m_rlc->Start ();
}

bool
LteSimpleNetDevice::Send (Ptr<Packet> packet, const Address& dest, uint16_t protocolNumber)
{
  NS_LOG_FUNCTION (this << dest << protocolNumber);
  return SimpleNetDevice::Send (packet, dest, protocolNumber);
}


} // namespace ns3
