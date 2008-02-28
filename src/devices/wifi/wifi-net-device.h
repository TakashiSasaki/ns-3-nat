/* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2005,2006 INRIA
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
 * Author: Mathieu Lacage <mathieu.lacage@sophia.inria.fr>
 */

#ifndef WIFI_NET_DEVICE_H
#define WIFI_NET_DEVICE_H

#include "ns3/net-device.h"
#include "ns3/packet.h"
#include "ns3/callback-trace-source.h"
#include "ns3/mac48-address.h"
#include "ssid.h"
#include <string>

namespace ns3 {

class WifiChannel;
class WifiPhy;
class MacStations;
class MacLow;
class MacRxMiddle;
class MacTxMiddle;
class WifiMacParameters;
class DcaTxop;
class MacHighAdhoc;
class MacHighNqsta;
class MacHighNqap;
class DcfManager;

/**
 * \brief hold the type of trace event generated by 
 * a WifiNetDevice.
 */
class WifiNetDeviceTraceType : public TraceContextElement
{
public:
  enum Type {
    RX,
    TX
  };
  WifiNetDeviceTraceType ();
  WifiNetDeviceTraceType (enum Type type);
  /**
   * \returns the type of event
   */
  enum Type Get (void) const;

  static uint16_t GetUid (void);
  void Print (std::ostream &os) const;
  std::string GetTypeName (void) const;
private:
  enum Type m_type;
};

/**
 * \brief the base class for 802.11 network interfaces
 *
 */
class WifiNetDevice : public NetDevice {
public:
  virtual ~WifiNetDevice ();

  /**
   * \param channel the channel to connect this 802.11 
   *        interface to.
   */
  void Attach (Ptr<WifiChannel> channel);

  /**
   * \returns the Mac48Address of this 802.11 interface.
   *
   * This method is equivalent to NetDevice::GetAddress. The only
   * difference is its return type.
   */
  Mac48Address GetSelfAddress (void) const;
  /**
   * \returns the bssid of this 802.11 interface.
   */
  virtual Mac48Address GetBssid (void) const = 0;
  /**
   * \returns the ssid of this 802.11 interface.
   */
  virtual Ssid GetSsid (void) const = 0;

  // inherited from NetDevice base class.
  virtual void SetName(const std::string name);
  virtual std::string GetName(void) const;
  virtual void SetIfIndex(const uint32_t index);
  virtual uint32_t GetIfIndex(void) const;
  virtual Ptr<Channel> GetChannel (void) const;
  virtual Address GetAddress (void) const;
  virtual bool SetMtu (const uint16_t mtu);
  virtual uint16_t GetMtu (void) const;
  virtual bool IsLinkUp (void) const;
  virtual void SetLinkChangeCallback (Callback<void> callback);
  virtual bool IsBroadcast (void) const;
  virtual Address GetBroadcast (void) const;
  virtual bool IsMulticast (void) const;
  virtual Address GetMulticast (void) const;
  virtual Address MakeMulticastAddress (Ipv4Address multicastGroup) const;
  virtual bool IsPointToPoint (void) const;
  virtual bool Send(Ptr<Packet> packet, const Address& dest, uint16_t protocolNumber);
  virtual Ptr<Node> GetNode (void) const;
  virtual bool NeedsArp (void) const;
  virtual void SetReceiveCallback (NetDevice::ReceiveCallback cb);

private:
  class PhyListener;
  class NavListener;

  // defined for children
  virtual void NotifyAttached (void) = 0;
  virtual bool DoSendTo (Ptr<const Packet> packet, const Mac48Address &to) = 0;
  // private helper
  void Construct (void);

  CallbackTraceSource<Ptr<const Packet>, Mac48Address> m_rxLogger;
  CallbackTraceSource<Ptr<const Packet>, Mac48Address> m_txLogger;
protected:
  WifiNetDevice (Ptr<Node> node, Mac48Address self);
  void DoForwardUp (Ptr<Packet> packet, const Mac48Address &from);
  Ptr<DcaTxop> CreateDca (uint32_t minCw, uint32_t maxCw, uint32_t aifsn) const;
  void NotifyLinkUp (void);
  void NotifyLinkDown (void);
  // inherited from Object
  virtual void DoDispose (void);
  // inherited from Object
  virtual Ptr<TraceResolver> GetTraceResolver (void) const;

  Ptr<WifiChannel> m_channel;
  Ptr<WifiPhy> m_phy;
  MacStations *m_stations;
  Ptr<MacLow> m_low;
  MacRxMiddle *m_rxMiddle;
  MacTxMiddle *m_txMiddle;
  WifiMacParameters *m_parameters;
  DcfManager *m_manager;
  PhyListener *m_phyListener;
  NavListener *m_navListener;

  Ptr<Node> m_node;
  Mac48Address m_address;
  NetDevice::ReceiveCallback m_rxCallback;
  uint32_t m_ifIndex;
  std::string m_name;
  bool m_linkUp;
  Callback<void> m_linkChangeCallback;
  uint16_t m_mtu;
};

/**
 * \brief a 802.11 adhoc network interface
 *
 * This network interface is a very simple pass-through 
 * from the higher layers down to the MAC DCF layer.
 */
class AdhocWifiNetDevice : public WifiNetDevice {
public:
  AdhocWifiNetDevice (Ptr<Node> node, Mac48Address self);
  virtual ~AdhocWifiNetDevice ();

  virtual Mac48Address GetBssid (void) const;
  virtual Ssid GetSsid (void) const;
  void SetSsid (Ssid ssid);

protected:
  // inherited from Object
  virtual void DoDispose (void);
private:
  void DoConstruct (void);
  void ForwardUp (void);
  // inherited from WifiNetDefice
  virtual bool DoSendTo (Ptr<const Packet> packet, Mac48Address const & to);
  virtual void NotifyAttached (void);
  virtual Ptr<TraceResolver> GetTraceResolver (void) const;

  Ssid m_ssid;
  Ptr<DcaTxop> m_dca;
  MacHighAdhoc *m_high;
};

/**
 * \brief a 802.11 STA network interface 
 *
 * This network interface implements the MAC-level STA 
 * active probing, association, and disassociation prototols.
 *
 * By default, it starts a new probing phase whenever a new 
 * data packet must be sent and the STA is not yet associated
 * to the AP.
 */
class NqstaWifiNetDevice : public WifiNetDevice 
{
public:
  /**
   * The ssid is initialized from \valueref{WifiSsid}.
   */
  NqstaWifiNetDevice (Ptr<Node> node, Mac48Address self);
  virtual ~NqstaWifiNetDevice ();

  virtual Mac48Address GetBssid (void) const;
  virtual Ssid GetSsid (void) const;

  /**
   * \param ssid the ssid we want to associate with
   *
   * Start a new active probing phase with the specified
   * ssid.
   */
  void StartActiveAssociation (Ssid ssid);
protected:
  // inherited from Object
  virtual void DoDispose (void);
private:
  void DoConstruct (void);
  void Associated (void);
  void DisAssociated (void);
  // inherited from WifiNetDefice
  virtual bool DoSendTo (Ptr<const Packet> packet, Mac48Address const & to);
  virtual void NotifyAttached (void);
  virtual Ptr<TraceResolver> GetTraceResolver (void) const;

  Ssid m_ssid;
  Ptr<DcaTxop> m_dca;
  MacHighNqsta *m_high;
};

/**
 * \brief a 802.11 AP network interface
 *
 * This network interface implements the MAC-level
 * AP-side of the beacon, probing, and, association
 * protocols. By default, every STA which tries
 * to associate is accepted.
 */
class NqapWifiNetDevice : public WifiNetDevice 
{
public:
  /**
   * The ssid is initialized from \valueref{WifiSsid}.
   */
  NqapWifiNetDevice (Ptr<Node> node);
  NqapWifiNetDevice (Ptr<Node> node, Mac48Address self);
  virtual ~NqapWifiNetDevice ();

  virtual Mac48Address GetBssid (void) const;
  virtual Ssid GetSsid (void) const;
  void SetSsid (Ssid ssid);
  void StartBeaconing (void);
protected:
  // inherited from Object
  virtual void DoDispose (void);
private:
  void DoConstruct (void);
  // inherited from WifiNetDefice
  virtual bool DoSendTo (Ptr<const Packet> packet, Mac48Address const & to);
  virtual void NotifyAttached (void);
  virtual Ptr<TraceResolver> GetTraceResolver (void) const;

  Ssid m_ssid;
  Ptr<DcaTxop> m_dca;
  Ptr<DcaTxop> m_beaconDca;
  MacHighNqap *m_high;
};

} // namespace ns3

#endif /* WIFI_NET_DEVICE_H */
