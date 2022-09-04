install: $(name).so
	install -d $(out)/lib/
	install $(name).so $(out)/lib/

$(name).so: gmpwrapper.c
	cc -shared -fPIC gmpwrapper.c -lgmp -o $(name).so
