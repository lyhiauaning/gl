all:
	zip tmp.zip ./code/* -q -j
	cat ./install/install.sh tmp.zip > ./install.bin
	rm tmp.zip

install: all
	make
	bash install.bin
	rm install.bin
