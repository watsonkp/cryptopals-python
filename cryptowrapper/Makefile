install: $(name).so
	install -d $(out)/lib/
	install $(name).so $(out)/lib/

$(name).so: cryptowrapper.c
	cc -shared -fPIC cryptowrapper.c -lcrypto -o $(name).so
