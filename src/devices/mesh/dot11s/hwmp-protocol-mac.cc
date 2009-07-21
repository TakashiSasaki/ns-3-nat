/* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2008,2009 IITP RAS
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
 * Author: Kirill Andreev <andreev@iitp.ru>
 */

#include "ns3/mesh-wifi-interface-mac.h"
#include "ns3/packet.h"
#include "ns3/simulator.h"
#include "ns3/nstime.h"
#include "ns3/log.h"
#include "dot11s-mac-header.h"
#include "hwmp-protocol.h"
#include "hwmp-protocol-mac.h"
#include "hwmp-tag.h"
#include "ie-dot11s-preq.h"
#include "ie-dot11s-prep.h"
#include "ie-dot11s-rann.h"

namespace ns3 {
namespace dot11s {

NS_LOG_COMPONENT_DEFINE ("HwmpProtocolMac");
HwmpProtocolMac::HwmpProtocolMac (uint32_t ifIndex, Ptr<HwmpProtocol> protocol):
  m_ifIndex (ifIndex),
  m_protocol (protocol)
{
}
HwmpProtocolMac::~HwmpProtocolMac ()
{
}
void
HwmpProtocolMac::SetParent (Ptr<MeshWifiInterfaceMac> parent)
{
  m_parent = parent;
}

bool
HwmpProtocolMac::ReceiveData (Ptr<Packet> packet, const WifiMacHeader & header)
{
  NS_ASSERT (header.IsData());

  MeshHeader meshHdr;
  HwmpTag tag;
  if (packet->PeekPacketTag (tag))
  {
    NS_FATAL_ERROR ("HWMP tag is not supposed to be received by network");
  }
  
  packet->RemoveHeader (meshHdr);
  m_stats.rxData ++;
  m_stats.rxDataBytes += packet->GetSize ();
  
  //TODO: address extension
  Mac48Address destination;
  Mac48Address source;
  switch (meshHdr.GetAddressExt ())
  {
    case 0:
      source = header.GetAddr4 ();
      destination = header.GetAddr3 ();
      break;
    default:
      NS_FATAL_ERROR ("6-address scheme is not yet supported and 4-address extension is not supposed to be used for data frames.");
  };
  tag.SetSeqno (meshHdr.GetMeshSeqno ());
  tag.SetTtl (meshHdr.GetMeshTtl ());
  packet->AddPacketTag (tag);
 
  if ((destination == Mac48Address::GetBroadcast ()) && (m_protocol->DropDataFrame (meshHdr.GetMeshSeqno (), source)))
    {
      return false;
    } 
  return true;
}

bool
HwmpProtocolMac::ReceiveAction (Ptr<Packet> packet, const WifiMacHeader & header)
{
  m_stats.rxMgt ++;
  m_stats.rxMgtBytes += packet->GetSize ();
  WifiMeshActionHeader actionHdr;
  packet->RemoveHeader (actionHdr);
  WifiMeshActionHeader::ActionValue actionValue = actionHdr.GetAction ();
  if (actionHdr.GetCategory () != WifiMeshActionHeader::MESH_PATH_SELECTION)
    {
      return true;
    }
  IeRann rann;
  IePreq preq;
  IePrep prep;
  IePerr perr;
  while (packet->RemoveHeader (rann))
  {
    NS_LOG_WARN("RANN is not supported!");
  }
  while (packet->RemoveHeader (preq))
  {
    m_stats.rxPreq ++;
    if (preq.GetOriginatorAddress () == m_protocol->GetAddress ())
      {
        continue;
      }
    if (preq.GetTtl () == 0)
      {
        continue;
      }
    preq.DecrementTtl ();
    m_protocol->ReceivePreq (preq, header.GetAddr2 (), m_ifIndex, header.GetAddr3 (), m_parent->GetLinkMetric(header.GetAddr2 ()));
  }
  while (packet->RemoveHeader (prep))
  {
    m_stats.rxPrep ++;
    if (prep.GetTtl () == 0)
      {
        continue;
      }
    prep.DecrementTtl ();
    m_protocol->ReceivePrep (prep, header.GetAddr2 (), m_ifIndex, header.GetAddr3 (), m_parent->GetLinkMetric(header.GetAddr2 ()));
  }
  std::vector<IePerr::FailedDestination> failedDestinations;
  while (packet->RemoveHeader (perr))
  {
    m_stats.rxPerr ++;
    std::vector<IePerr::FailedDestination> destinations = perr.GetAddressUnitVector ();
    for(std::vector<IePerr::FailedDestination>::const_iterator i = destinations.begin (); i != destinations.end (); i ++)
      failedDestinations.push_back (*i);
  }
  if (failedDestinations.size () > 0)
    {
      m_protocol->ReceivePerr (failedDestinations, header.GetAddr2 (), m_ifIndex, header.GetAddr3 ());
    }
  NS_ASSERT(packet->GetSize () == 0);
  return false;
}

bool
HwmpProtocolMac::Receive (Ptr<Packet> packet, const WifiMacHeader & header)
{
  if (header.IsData ())
    {
      return ReceiveData (packet, header);
    }
  else 
    {
      if (header.IsAction ())
        {
          return ReceiveAction (packet, header);
        }
      else
        {
          return true; // don't care
        }
    }
}
bool
HwmpProtocolMac::UpdateOutcomingFrame (Ptr<Packet> packet, WifiMacHeader & header, Mac48Address from, Mac48Address to)
{
  if (!header.IsData ())
    {
      return true;
    }
  HwmpTag tag;
  bool tagExists = packet->RemovePacketTag(tag);
  if (!tagExists)
  {
    NS_FATAL_ERROR ("HWMP tag must exist at this point");
  }
  m_stats.txData ++;
  m_stats.txDataBytes += packet->GetSize ();
  MeshHeader meshHdr;
  meshHdr.SetMeshSeqno (tag.GetSeqno ());
  meshHdr.SetMeshTtl (tag.GetTtl());
  packet->AddHeader (meshHdr);
  header.SetAddr1 (tag.GetAddress());
  return true;
}
WifiMeshActionHeader
HwmpProtocolMac::GetWifiMeshActionHeader ()
{
  WifiMeshActionHeader actionHdr;
  WifiMeshActionHeader::ActionValue action;
  action.pathSelection = WifiMeshActionHeader::PATH_SELECTION;
  actionHdr.SetAction (WifiMeshActionHeader::MESH_PATH_SELECTION, action);
  return actionHdr;
}
void
HwmpProtocolMac::SendPreq (IePreq preq)
{
  NS_LOG_FUNCTION_NOARGS ();
  std::vector<IePreq> preq_vector;
  preq_vector.push_back(preq);
  SendPreq(preq_vector);
}
void
HwmpProtocolMac::SendPreq(std::vector<IePreq> preq)
{
  Ptr<Packet> packet = Create<Packet> ();
  for(std::vector<IePreq>::const_iterator i = preq.begin (); i != preq.end (); i ++)
  {
    packet->AddHeader (*i);
  }
  packet->AddHeader (GetWifiMeshActionHeader ());
  //create 802.11 header:
  WifiMacHeader hdr;
  hdr.SetAction ();
  hdr.SetDsNotFrom ();
  hdr.SetDsNotTo ();
  hdr.SetAddr2 (m_parent->GetAddress ());
  hdr.SetAddr3 (m_protocol->GetAddress ());
  //Send Management frame
  std::vector <Mac48Address> receivers = m_protocol->GetPreqReceivers (m_ifIndex);
  for (std::vector<Mac48Address>::const_iterator i = receivers.begin (); i != receivers.end (); i ++)
  {
    hdr.SetAddr1 (*i);
    m_stats.txPreq ++;
    m_stats.txMgt ++;
    m_stats.txMgtBytes += packet->GetSize ();
    m_parent->SendManagementFrame (packet, hdr);
  }
}
void
HwmpProtocolMac::RequestDestination (Mac48Address dst, uint32_t originator_seqno, uint32_t dst_seqno)
{
  NS_LOG_FUNCTION_NOARGS ();
  for (std::vector<IePreq>::iterator i = m_myPreq.begin (); i != m_myPreq.end(); i ++)
  {
    if (i->IsFull ())
      {
        continue;
      }
    NS_ASSERT (i->GetDestCount () > 0);
    i->AddDestinationAddressElement (m_protocol->GetDoFlag(), m_protocol->GetRfFlag(), dst, dst_seqno);
  }
  IePreq preq;
  preq.SetHopcount (0);
  preq.SetTTL (m_protocol->GetMaxTtl ());
  preq.SetPreqID (m_protocol->GetNextPreqId ());
  preq.SetOriginatorAddress (m_protocol->GetAddress ());
  preq.SetOriginatorSeqNumber (originator_seqno);
  preq.SetLifetime (m_protocol->GetActivePathLifetime ());
  preq.AddDestinationAddressElement (m_protocol->GetDoFlag(), m_protocol->GetRfFlag(), dst, dst_seqno);
  m_myPreq.push_back(preq);
  SendMyPreq ();
}
void
HwmpProtocolMac::SendMyPreq ()
{
  NS_LOG_FUNCTION_NOARGS ();
  if (m_preqTimer.IsRunning ())
    {
      return;
    }
  if (m_myPreq.size () == 0)
    {
      return;
    }
  //reschedule sending PREQ
  NS_ASSERT (!m_preqTimer.IsRunning());
  m_preqTimer = Simulator::Schedule (m_protocol->GetPreqMinInterval (), &HwmpProtocolMac::SendMyPreq, this);
  SendPreq (m_myPreq);
  m_myPreq.clear ();
}
void
HwmpProtocolMac::SendPrep (IePrep prep, Mac48Address receiver)
{
  NS_LOG_FUNCTION_NOARGS ();
  //Create packet
  Ptr<Packet> packet  = Create<Packet> ();
  packet->AddHeader (prep);
  packet->AddHeader (GetWifiMeshActionHeader ());
  //create 802.11 header:
  WifiMacHeader hdr;
  hdr.SetAction ();
  hdr.SetDsNotFrom ();
  hdr.SetDsNotTo ();
  hdr.SetAddr1 (receiver);
  hdr.SetAddr2 (m_parent->GetAddress ());
  hdr.SetAddr3 (m_protocol->GetAddress ());
  //Send Management frame
  m_stats.txPrep ++;
  m_stats.txMgt ++;
  m_stats.txMgtBytes += packet->GetSize ();
  m_parent->SendManagementFrame(packet, hdr);
}
void
HwmpProtocolMac::ForwardPerr(std::vector<IePerr::FailedDestination> failedDestinations, std::vector<Mac48Address> receivers)
{
  NS_LOG_FUNCTION_NOARGS ();
  Ptr<Packet> packet  = Create<Packet> ();
  IePerr perr;
  for (std::vector<IePerr::FailedDestination>::const_iterator i = failedDestinations.begin (); i != failedDestinations.end (); i ++)
  {
    if (!perr.IsFull ())
      {
        perr.AddAddressUnit (*i);
      }
    else
      {
        packet->AddHeader (perr);
        perr.ResetPerr ();
      }
  }
  if (perr.GetNumOfDest () > 0)
    {
      packet->AddHeader (perr);
    }
  packet->AddHeader (GetWifiMeshActionHeader ());
  //create 802.11 header:
  WifiMacHeader hdr;
  hdr.SetAction ();
  hdr.SetDsNotFrom ();
  hdr.SetDsNotTo ();
  hdr.SetAddr2 (m_parent->GetAddress ());
  hdr.SetAddr3 (m_protocol->GetAddress ());
  if(receivers.size () >= m_protocol->GetUnicastPerrThreshold ())
  {
    receivers.clear ();
    receivers.push_back (Mac48Address::GetBroadcast ());
  }
  //Send Management frame
  for (std::vector<Mac48Address>::const_iterator i = m_myPerr.receivers.begin (); i != m_myPerr.receivers.end (); i ++)
  {
    hdr.SetAddr1 (*i);
    m_stats.txPerr ++;
    m_stats.txMgt ++;
    m_stats.txMgtBytes += packet->GetSize ();
    m_parent->SendManagementFrame(packet, hdr);
  }
}
void
HwmpProtocolMac::InitiatePerr (std::vector<IePerr::FailedDestination> failedDestinations, std::vector<Mac48Address> receivers)
{
  //All duplicates in PERR are checked here, and there is no reason to
  //check it at any athoer place
{
  std::vector<Mac48Address>::const_iterator end = receivers.end();
  for(std::vector<Mac48Address>::const_iterator i = receivers.begin (); i != end; i ++)
    {
      bool should_add = true;
      for (std::vector<Mac48Address>::const_iterator j = m_myPerr.receivers.begin (); j != m_myPerr.receivers.end (); j ++)
      {
        if ((*i) == (*j))
        {
          should_add = false;
        }
      }
      if (should_add)
      {
        m_myPerr.receivers.push_back(*i);
      }
    }
}
{
  std::vector<IePerr::FailedDestination>::const_iterator end =  failedDestinations.end ();
  for(std::vector<IePerr::FailedDestination>::const_iterator i = failedDestinations.begin (); i != end; i ++)
    {
      bool should_add = true;
      for (std::vector<IePerr::FailedDestination>::const_iterator j = m_myPerr.destinations.begin (); j != m_myPerr.destinations.end (); j ++)
        {
          if ( ((*i).destination == (*j).destination) && ((*j).seqnum > (*i).seqnum) )
            {
              should_add = false;
            }
        }
      if (should_add)
        {
          m_myPerr.destinations.push_back(*i);
        }
    }
}
  SendMyPerr ();
}
void
HwmpProtocolMac::SendMyPerr()
{
  NS_LOG_FUNCTION_NOARGS ();
  if (m_perrTimer.IsRunning ())
    {
      return;
    }
  m_perrTimer = Simulator::Schedule (m_protocol->GetPerrMinInterval (), &HwmpProtocolMac::SendMyPerr, this);
  ForwardPerr (m_myPerr.destinations, m_myPerr.receivers);
  m_myPerr.destinations.clear ();
  m_myPerr.receivers.clear ();
}
uint32_t
HwmpProtocolMac::GetLinkMetric(Mac48Address peerAddress) const
{
  return m_parent->GetLinkMetric (peerAddress);
}
uint16_t
HwmpProtocolMac::GetChannelId () const
{
  return m_parent->GetFrequencyChannel ();
}
HwmpProtocolMac::Statistics::Statistics () :
  txPreq (0), 
  rxPreq (0),
  txPrep (0),
  rxPrep (0),
  txPerr (0),
  rxPerr (0),
  txMgt (0),
  txMgtBytes (0),
  rxMgt (0),
  rxMgtBytes (0),
  txData (0),
  txDataBytes (0),
  rxData (0),
  rxDataBytes (0)
{}
void
HwmpProtocolMac::Statistics::Print (std::ostream & os) const
{
  os << "<Statistics "
    "txPreq= \"" << txPreq << "\"\n"
    "txPrep=\"" << txPrep << "\"\n"
    "txPerr=\"" << txPerr << "\"\n"
    "rxPreq=\"" << rxPreq << "\"\n"
    "rxPrep=\"" << rxPrep << "\"\n"
    "rxPerr=\"" << rxPerr << "\"\n"
    "txMgt=\"" << txMgt << "\"\n"
    "txMgtBytes=\"" << txMgtBytes  << "\"\n"
    "rxMgt=\"" << rxMgt << "\"\n"
    "rxMgtBytes=\"" << rxMgtBytes << "\"\n"
    "txData=\"" << txData << "\"\n"
    "txDataBytes=\"" << txDataBytes << "\"\n"
    "rxData=\"" << rxData << "\"\n"
    "rxDataBytes=\"" << rxDataBytes << "\"/>\n";
}
void
HwmpProtocolMac::Report (std::ostream & os) const
{
  os << "<HwmpProtocolMac\n"
    "address =\""<< m_parent->GetAddress () <<"\">\n";
  m_stats.Print(os);
  os << "</HwmpProtocolMac>\n";
}
void
HwmpProtocolMac::ResetStats ()
{
  m_stats = Statistics::Statistics ();
}

} //namespace dot11s
}//namespace ns3
