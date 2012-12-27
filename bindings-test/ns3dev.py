#!/usr/bin/python
from __future__ import print_function
import importlib

modules = ("antenna", "aodv", "applications", "bridge", "buildings", "config_store", "core", "csma", "csma_layout",
           "dsdv", "dsr", "emu", "energy", "flow_monitor", "internet", "lte", "mesh", "mobility", "nix_vector_routing",
           "olsr", "point_to_point", "point_to_point_layout", "propagation", "spectrum", "stats", "tap_bridge",
           "tools", "topology_read", "uan", "virtual_net_device", "visualizer", "wifi", "wimax")

modules = ("internet",)

for x in modules:
    try:
        print("importing %s" % x, end="")
        importlib.import_module("ns.%s"%x)
	print(" done")
    except Exception, e: 
	print(" failed")

