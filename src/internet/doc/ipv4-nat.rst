Network Address Translation (NAT)
---------------------------------

.. heading hierarchy:
   ------------- Chapter
   ************* Section (#.#)
   ============= Subsection (#.#.#)
   ############# Paragraph (no number)

Network address translation(NAT) is a process of altering the source/destination ip address of a packet in order to make it routable over a network. This is usually applied when packets are passed through a public network.
Network address translation is also used in ip address hiding where hosts can be on the ip behind the nat device and cannot be directly connected to from an external network. NAT also comes with a number of variants in terms of 
what felid of the packet is put through NAT(e.g. Port Numbers) or the directions of the NAT(e.g. Unidirectional vs Bidirectional).

Model Description
*****************

The source code for this model lives in the directory ``src/internet/model``.

Design
======

The design of NAT for NS-3 is basically divided into two main categories: 

Static NAT :  This type of NAT is biderectional. It is designed to perform host to host nat and also has a variant to specify the nat for specific protocol and port.
The NAT is defined by a class Ipv4StaticNatRule class which defines the structure of the static rule. This is then stored in a list for static rules.

Dynamic NAT:

Scope and Limitations
=====================

-The NAT is currently limited to host-to-host. It can be extended from network to network.
-The NAT is not completely bound with connection tracking. This also needs some work.

References
==========

http://hasenstein.com/linux-ip-nat/nat-document.pdf

Usage
*****
The usage of the NAT code is primarily done by creating the nat object and adding rules to the table.
The following are the steps of things to be done when converting a node to a nat node:
 
Create the NAT object .
   Ptr<Ipv4Nat> nat = CreateObject<Ipv4Nat> ();

Aggregate the NAT object to a node; this will hook it to Ipv4Netfilter.
    second.Get (0)->AggregateObject (nat);

Define the inside and the outside interfaces of the node. These are the interfaces between which the nat will be processed.
   nat->SetInside (1);
   nat->SetOutside (2);

Add the rules next
  Ipv4StaticNatRule rule (Ipv4Address ("192.168.1.1"), Ipv4Address ("203.82.48.100"));
  nat->AddStaticRule (rule);

The following code will help printing the nat rules to a file nat.routes from the stream. 
  Ptr<OutputStreamWrapper> natStream = Create<OutputStreamWrapper> ("nat.routes", std::ios::out);
  nat->PrintTable (natStream);

The above illustrates a typical example of a one to one static nat. The other variant in the static nat rule with the ports can be defined
   Ipv4StaticNatRule rule2 (Ipv4Address ("192.168.2.3"), uint16_t (80),Ipv4Address ("10.1.3.4"), uint16_t (8080), uint16_t (0));
   nat->AddStaticRule (rule2);

Helper
======



Attributes
==========


Advanced Usage
==============


Examples
========

The following example have been written, which can be found in ``src/internet/examples``:

* ipv4-nat-example.cc : This example basically illustrates a three node architecture where the middle node is a nat device. The static nat rule is added to the nat table and printed out to a nat.routes document.

Validation
**********
Basic tests for adding and removing the nat rules are in place.

