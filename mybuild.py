#!/usr/bin/python3
import os

if __name__ == "__main__":
    while True:
        print("t : configure with --enable-tests")
        print("e : configure with --enable-tests --enable-examples")
        print("c : clean up all")
        a = input("Input a character to go ahead. Just type enter to quit : ")
        if a == "":
            print("Bye ... ")
            exit()
        if a == "t":
       	    os.system("./waf configure --enable-tests")
            os.system("./waf")
        if a == "e":
            os.system("./waf configure --enable-tests --enable-exmaples")
            os.system("./waf")
    
