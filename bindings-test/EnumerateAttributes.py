#!/usr/bin/python
#import ns3
import sys, importlib, pydoc, re

#print(sys.modules.keys())
#print(importlib.__import__())

ns3_313_ubuntu_modules = ["antenna", "aodv", "applications", "bridge", "buildings",
                          "config_store", "core", "csma", "csma_layout",
                          "dsdv", "dsr", "emu", "energy", "flow_monitor", "internet",
                          "lte", "mesh", "mobility", "nix_vector_routing",
                          "olsr", "point_to_point", "point_to_point_layout",
                          "propagation", "spectrum", "stats", "tap_bridge",
                          "tools", "topology_read", "uan", "virtual_net_device",
                          "visualizer", "wifi", "wimax"]

modules = []
def callback(path, modname, desc, modules=modules):
    #print("path=%s" % path)
    if re.match("ns\\.", modname): 
        if modname not in modules:
            modules.append(modname)
        #print("modname=%s" % modname)
    #print("desc=%s" % desc)
    #print("modules=%s" % modules)
    
#    if modname and modname[-9:] == ".__init__":
#        modname = modname[:-9]
#    if modname.find(".") < 0 and modname not in modules:
#        modules.append(modname)


def onerror(modname):
    callback(None, modname, None)

pydoc.ModuleScanner().run(callback, onerror=onerror)
#print (modules)

#f = open("bound_attributes.txt", "w")
for m in modules:
    x = importlib.import_module(m)
    attributes = dir(x) 
    for a in attributes:
        print(x.__name__ + "." + a)


