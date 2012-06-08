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
 */

#include "ns3/core-module.h"
#include "ns3/simulator-module.h"
#include "ns3/node-module.h"
#include "ns3/helper-module.h"
#include "ns3/global-route-manager.h"
#include "ns3/on-off-helper.h"
#include "ns3/v4ping-helper.h"
#include "ns3/ipv4-l3-protocol.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("NetfilterExample");

  int 
main (int argc, char *argv[])
{
  LogComponentEnable("UdpEchoClientApplication", LOG_LEVEL_INFO);
  LogComponentEnable("UdpEchoServerApplication", LOG_LEVEL_INFO);

  uint16_t port = 9;

  NodeContainer first;
  first.Create (3);

  NodeContainer second;
  second.Add ( first.Get (1) );
  second.Create (1);
  
  NodeContainter third;
  third.Add ( first.Get (2) );
  third.Create(2);


  Packet::EnablePrinting();

  PointToPointHelper pointToPoint;
  pointToPoint.SetDeviceAttribute ("DataRate", StringValue ("5Mbps"));
  pointToPoint.SetChannelAttribute ("Delay", StringValue ("2ms"));

  NetDeviceContainer devices1;
  devices1 = pointToPoint.Install (first);
  
  NetDeviceContainer devices2;
  devices2 = pointToPoint.Install (second);

  NetDeviceContainer devices3;
  devices3= pointToPoint.Install (third);

  InternetStackHelper stack;
  stack.Install (first);
  stack.Install (second.Get(1));
  stack.Install (third.Get(2));

  Ipv4AddressHelper address1;
  address1.SetBase ("192.168.1.1", "255.255.255.0");
  
  Ipv4AddressHelper address2;
  address2.SetBase ("25.25.25.1", "255.255.255.0");
  
  Ipv4AddressHelper address3;
  address2.SetBase ("25.25.25.2", "255.255.255.0");

  Ipv4AddressHelper address4;
  address2.SetBase ("10.1.1.1", "255.255.255.0");


  Ipv4InterfaceContainer firstInterfaces = address1.Assign (devices1);
  Ipv4InterfaceContainer secondInterfaces = address2.Assign (devices2);
  Ipv4InterfaceContainer secondInterfaces = address3.Assign (devices2);
  Ipv4InterfaceContainer secondInterfaces = address4.Assign (devices3);

  Ptr <Ipv4> ipv4 = first.Get (1)->GetObject<Ipv4> ();
  std::cout << "Number of interfaces on node " << first.Get (1)->GetId () << ": " << ipv4->GetNInterfaces () << std::endl;


 /* Ptr <Ipv4L3Protocol> ipv4L3 = DynamicCast <Ipv4L3Protocol>(first.Get (1)->GetObject<Ipv4> ());
  Ipv4Netfilter *netfilter = ipv4L3->GetNetfilter ();
  netfilter->EnableNat ();
  std::cout << "Adding rule at node " << first.Get (1)->GetId () << ", device " << first.Get (1)->GetDevice (1)->GetIfIndex () << std::endl;
  netfilter->AddNatRule ( NatRule (Ipv4Address ("192.168.1.1"), Ipv4Address ("203.82.48.1"), first.Get (1)->GetDevice (1)));
*/
  UdpEchoServerHelper echoServer (9);

  ApplicationContainer serverApps = echoServer.Install (second.Get (1));
  serverApps.Start (Seconds (1.0));
  serverApps.Stop (Seconds (10.0));

  UdpEchoClientHelper echoClient (secondInterfaces.GetAddress (1), 9);
  echoClient.SetAttribute ("MaxPackets", UintegerValue (1));
  echoClient.SetAttribute ("Interval", TimeValue (Seconds (1.)));
  echoClient.SetAttribute ("PacketSize", UintegerValue (512));

  ApplicationContainer clientApps = echoClient.Install (first.Get (0));
  clientApps.Start (Seconds (2.0));
  clientApps.Stop (Seconds (10.0));

  OnOffHelper onOff ( "ns3::TcpSocketFactory", 
                      Address (InetSocketAddress ("192.168.1.1", port)));
  onOff.SetAttribute ("MaxBytes", UintegerValue (512));

  ApplicationContainer onOffApp = onOff.Install (second.Get (1));

  PacketSinkHelper packetSink ( "ns3::TcpSocketFactory",
                                Address (InetSocketAddress ("192.168.1.1", port)));

  ApplicationContainer packetSinkApp = packetSink.Install (first.Get (0));

  /*packetSinkApp.Start (Seconds (2.0));
  packetSinkApp.Stop (Seconds (4.0));

  onOffApp.Start (Seconds (3.0));
  onOffApp.Stop (Seconds (4.0));*/

  /*ApplicationContainer pingApp = ping.Install (first.Get (0));
  pingApp.Start (Seconds (3.0));
  pingApp.Stop (Seconds (4.0));*/

  GlobalRouteManager::PopulateRoutingTables ();

  PointToPointHelper::EnablePcapAll ("netfilter");

  Simulator::Run ();
  Simulator::Destroy ();
  return 0;
}
