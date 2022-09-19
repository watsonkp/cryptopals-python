install: lib$(name).so
	install -d $(out)/lib/
	install lib$(name).so $(out)/lib/

lib$(name).so: cryptowrapper.c
	cc -shared -fPIC cryptowrapper.c -lcrypto -o lib$(name).so
