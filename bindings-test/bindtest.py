#!/usr/bin/python
#import ns3
import sys, importlib, pydoc

print(sys.modules.keys())
#print(importlib.__import__())

modules= []

def callback(path, modname, desc, modules=modules):
#    if modname and modname[-9:] == ".__init__":
#        modname = modname[:-9]
#    if modname.find(".") < 0 and modname not in modules:
#        modules.append(modname)
    if modname not in modules:
        modules.append(modname)

def onerror(modname):
    callback(None, modname, None)

pydoc.ModuleScanner().run(callback)
print (modules)

