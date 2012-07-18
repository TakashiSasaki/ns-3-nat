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
#include "nat-rule.h"

namespace ns3 {
    
NatRule::NatRule (Ipv4Address orig, Ipv4Address mapped, Ptr<NetDevice> device) //, Ipv4Interface outInterface
{
  m_originalSource = orig;
  m_mangledSource = mapped;
  m_device = device;
  //m_outInterface = outInterface;
}
    
bool 
NatRule::operator == (const NatRule& other) const
{
  return (m_originalSource == other.m_originalSource) &&
            (m_mangledSource == other.m_mangledSource) &&
              (m_device == other.m_device);
  //            (m_outInterface == other.m_outInterface);
}
    
Ipv4Address 
NatRule::GetOriginalSource () const
{
  return m_originalSource;
}

Ipv4Address 
NatRule::GetMangledSource () const
{
  return m_mangledSource;
}

Ptr<NetDevice> 
NatRule::GetDevice () const
{
  return m_device;
}

}
