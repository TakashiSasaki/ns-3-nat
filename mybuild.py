#!/usr/bin/python3
import os

if __name__ == "__main__":
    while True:
        print("t : configure with --enable-tests")
        print("e : configure with --enable-tests --enable-examples --enable-mpi")
        print("c : clean up all")
        a = input("Input a character to go ahead. Just type enter to quit : ")
        if a == "":
            print("Bye ... ")
            exit()

        if a == "t":
       	    os.system("./waf configure --enable-tests")
            os.system("./waf")
            os.system("./test.py")
            print("t : finished")

        if a == "e":
            os.system("./waf configure --enable-tests --enable-examples")
            os.system("./waf")
            os.system("./test.py")
            print("e : finished")

        if a == "c":
            os.system("rm .hgignore")
            os.system("hg purge --all")
            os.system("hg revert .hgignore")
            os.system("hg status")
            print("c : finished")
 
