/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright 2012 University of Washington
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
 */

#include "ns3/test.h"
#include "ns3/ptr.h"
#include "ns3/object.h"
#include "ns3/ipv4-nat.h"
#include "ns3/ipv4-address.h"

using namespace ns3;

class Ipv4NatAddRemoveRules : public TestCase
{
public:
  Ipv4NatAddRemoveRules ();
  virtual ~Ipv4NatAddRemoveRules ();

private:
  virtual void DoRun (void);
};

Ipv4NatAddRemoveRules::Ipv4NatAddRemoveRules ()
  : TestCase ("Add and remove NAT rules from object")
{
}

Ipv4NatAddRemoveRules::~Ipv4NatAddRemoveRules ()
{
}

void
Ipv4NatAddRemoveRules::DoRun (void)
{
  Ptr<Ipv4Nat> nat = CreateObject<Ipv4Nat> ();
  NS_TEST_ASSERT_MSG_EQ (nat->GetNStaticRules (), 0, "list is not initialized empty");
  Ipv4StaticNatRule rule1 (Ipv4Address ("10.1.2.3"), Ipv4Address ("192.168.4.5"));
  Ipv4StaticNatRule rule2 (Ipv4Address ("10.1.2.4"), Ipv4Address ("192.168.4.6"));
  nat->AddStaticRule (rule1);
  nat->AddStaticRule (rule2);
  NS_TEST_ASSERT_MSG_EQ (nat->GetNStaticRules (), 2, "adding to list failed");

  nat->RemoveStaticRule (1);  // should remove the 10.1.2.3 rule, as 10.1.2.4 pushed it down the stack
  NS_TEST_ASSERT_MSG_EQ (nat->GetNStaticRules (), 1, "removing from list failed");
  Ipv4StaticNatRule returnRule = nat->GetStaticRule (0);
  NS_TEST_ASSERT_MSG_EQ (returnRule.GetLocalIp (), Ipv4Address ("10.1.2.4"), "fetching from list failed");

  Ipv4StaticNatRule rule3 (Ipv4Address ("192.168.0.1"), Ipv4Address ("192.168.0.1"));
  nat->AddStaticRule (rule3);

}

class Ipv4NatTestSuite : public TestSuite
{
public:
  Ipv4NatTestSuite ();
};

Ipv4NatTestSuite::Ipv4NatTestSuite ()
  : TestSuite ("ipv4-nat", UNIT)
{
  AddTestCase (new Ipv4NatAddRemoveRules);
}

static Ipv4NatTestSuite ipv4NatTestSuite;

