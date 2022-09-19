install: lib$(name).so
	install -d $(out)/lib/
	install lib$(name).so $(out)/lib/

lib$(name).so: gmpwrapper.c
	cc -shared -fPIC gmpwrapper.c -lgmp -o lib$(name).so
