#!/bin/bash

gcc -shared -fPIC\
	cryptowrapper.c -lcrypto\
	-o libcryptowrapper.so
