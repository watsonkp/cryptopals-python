#!/bin/bash

gcc -I/home/sulliedeclat/bounty/tools/openssl/build/1.1/opt/openssl/include cryptowrapper.c -L/home/sulliedeclat/bounty/tools/openssl/build/1.1/opt/openssl/lib -l crypto -o cryptowrapper
