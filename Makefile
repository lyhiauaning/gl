all:
	shc -v -r -f code/xml2ass.sh -o code-2/xml2ass
	mv code/xml2ass.sh.x.c code-c/
	shc -v -r -f code/vahb.sh -o code-2/vahb
	mv code/vahb.sh.x.c code-c/
	shc -v -r -f code/gl-old.sh -o code-2/glo
	mv code/gl-old.sh.x.c code-c/
	shc -v -r -f code/gl.sh -o code-2/xml2ass
	mv code/gl.sh.x.c code-c/
	zip tmp.zip ./code-2/* -q -j
	cat ./install/install.sh tmp.zip > ./install.bin
	rm tmp.zip

install: all
	make
	bash install.bin
	rm install.bin
