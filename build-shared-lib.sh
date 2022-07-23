#!/bin/bash

gcc -shared -fPIC\
	-I/home/sulliedeclat/source/openssl-1.1.1q/build/include\
	-L/home/sulliedeclat/source/openssl-1.1.1q/build/lib\
	cryptowrapper.c -lcrypto\
	-o libcryptowrapper.so

# Old paths
#gcc -shared -fPIC\
#	-I/home/sulliedeclat/bounty/tools/openssl/build/1.1/opt/openssl/include\
#	-L/home/sulliedeclat/bounty/tools/openssl/build/1.1/opt/openssl/lib\
#	cryptowrapper.c -lcrypto\
#	-o libcryptowrapper.so
