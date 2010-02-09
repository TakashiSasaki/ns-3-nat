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

#include <time.h>
#include <sys/time.h>
#include <iostream>
#include <fstream>
#include <limits>

#include "ns3/simulator-module.h"
#include "ns3/node-module.h"
#include "ns3/core-module.h"
#include "ns3/helper-module.h"
#include "ns3/pcap-writer.h"

using namespace ns3;

static const uint64_t US_PER_NS = (uint64_t)1000;
static const uint64_t US_PER_SEC = (uint64_t)1000000;
static const uint64_t NS_PER_SEC = (uint64_t)1000000000;

uint64_t
GetRealtimeInNs (void)
{
  struct timeval tv;
  gettimeofday (&tv, NULL);

  uint64_t nsResult = tv.tv_sec * NS_PER_SEC + tv.tv_usec * US_PER_NS;
  return nsResult;
}

bool g_passheader = true;
bool g_addheader = true;

RadiotapHeader g_header;

Time g_t(0.);

void
PerfPcapNew (Ptr<PcapFileObject> file, Ptr<Packet> p, uint32_t n)
{
  if (g_passheader)
    {
      for (uint32_t i = 0; i < n; ++i)
        {
          if (g_passheader)
            {
              file->Write (g_t, g_header, p);
            }
        }
    }
  else
    {
      for (uint32_t i = 0; i < n; ++i)
        {
          if (g_addheader)
            {
              Ptr<Packet> pc = p->Copy ();
              pc->AddHeader (g_header);
              file->Write (g_t, pc);
            }
          else
            {
              file->Write (g_t, p);
            }
        }
    }
}

void
PerfPcapOld (PcapWriter &pcapWriter, Ptr<Packet> p, uint32_t n)
{

  for (uint32_t i = 0; i < n; ++i)
    {
      if (g_addheader)
        {
          pcapWriter.WriteWifiMonitorPacket (p, 0, 0, 0, true, false, 0., 0.);
        }
      else
        {
          pcapWriter.WritePacket (p);
        }
    }
}

int 
main (int argc, char *argv[])
{
  uint32_t n = 100000;
  uint32_t iter = 50;
  bool oldstyle = false;

  CommandLine cmd;
  cmd.AddValue ("addheader", "Add a header to the traces to trigger a deep copy", g_addheader);
  cmd.AddValue ("passheader", "Pass header as reference instead of adding it", g_passheader);
  cmd.AddValue ("n", "How many packets to write (defaults to 100000", n);
  cmd.AddValue ("iter", "How many times to run the test looking for a min (defaults to 50)", iter);
  cmd.AddValue ("oldstyle", "run the old style pcap writer stuff if true", oldstyle);
  cmd.Parse (argc, argv);

  uint64_t result = std::numeric_limits<uint64_t>::max ();
  
  if (oldstyle)
    {
      Ptr<Packet> p = Create<Packet> (1024);

      //
      // This will probably run on a machine doing other things.  Run it some
      // relatively large number of times and try to find a minimum, which
      // will hopefully represent a time when it runs free of interference.
      //
      for (uint32_t i = 0; i < iter; ++i)
        {
          PcapWriter pcapWriter;
          pcapWriter.Open ("perf-pcap.pcap");
          pcapWriter.WriteWifiRadiotapHeader ();

          uint64_t start = GetRealtimeInNs ();
          PerfPcapOld (pcapWriter, p, n);
          uint64_t et = GetRealtimeInNs () - start;
          result = std::min (result, et);
          std::cout << "."; std::cout.flush ();
        }
      std::cout << std::endl;
    }
  else
    {
      g_header.SetTsft (0);
      g_header.SetFrameFlags (RadiotapHeader::FRAME_FLAG_SHORT_PREAMBLE);
      g_header.SetRate (0);
      g_header.SetChannelFrequencyAndFlags (0, 0);

      //
      // This will probably run on a machine doing other things.  Run it some
      // relatively large number of times and try to find a minimum, which
      // will hopefully represent a time when it runs free of interference.
      //
      for (uint32_t i = 0; i < iter; ++i)
        {
          PcapHelper pcapHelper;
          Ptr<PcapFileObject> file = pcapHelper.CreateFile ("perf-pcap.pcap", "w", PcapHelper::DLT_IEEE802_11_RADIO);  
          Ptr<Packet> p = Create<Packet> (1024);

          uint64_t start = GetRealtimeInNs ();
          PerfPcapNew (file, p, n);
          uint64_t et = GetRealtimeInNs () - start;
          result = std::min (result, et);
          std::cout << "."; std::cout.flush ();
        }
      std::cout << std::endl;
    }
  std::cout << argv[0] << ": " << result << "ns" << std::endl;
}
