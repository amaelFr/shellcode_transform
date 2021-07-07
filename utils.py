#!/usr/bin/python3

from sys import exit

def error(msg):
    print("\033[31mError: {}\033[0m".format(msg))
    exit(1)