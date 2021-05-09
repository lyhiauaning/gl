all:
	echo "请执行\"make install\"进行安装"

encode:
	shc -v -r -f code/xml2ass.sh -o code-2/xml2ass
	mv code/xml2ass.sh.x.c code-c/
	shc -v -r -f code/vahb.sh -o code-2/vahb
	mv code/vahb.sh.x.c code-c/
	shc -v -r -f code/gl-old.sh -o code-2/glo
	mv code/gl-old.sh.x.c code-c/
	shc -v -r -f code/gl.sh -o code-2/gl
	mv code/gl.sh.x.c code-c/
	zip gl.zip ./code-2/* -q -j
	

install: encode 
	@if [ ! -d "${PREFIX}/etc/gl" ];then mkdir ${PREFIX}/etc/gl ; fi
	unzip gl.zip
	mv danmaku2ass ${PREFIX}/etc/gl
	mv gl.conf ${PREFIX}/etc/gl
	mv gl ${PREFIX}/bin/gl
	mv glo ${PREFIX}/bin/glo
	mv xml2ass ${PREFIX}/bin/xml2ass
	mv vahb ${PREFIX}/bin/vahb
	chmod a+x ${PREFIX}/bin/gl
	chmod a+x ${PREFIX}/bin/glo
	chmod a+x ${PREFIX}/bin/xml2ass
	chmod a+x ${PREFIX}/bin/vahb
	apt update
	@if [ ! -f "${PREFIX}/bin/python" ];then apt install python -y ; fi
	@if [ ! -f "${PREFIX}/bin/ffmpeg" ];then apt install ffmpeg -y ; fi
	@if [ ! -f "${PREFIX}/bin/jq" ];then apt install jq -y ; fi
	rm gl.zip
	@echo "Installation of GL is complete!"

remove:
	@rm -rf ${PREFIX}/etc/gl
	@rm ${PREFIX}/bin/gl
	@rm ${PREFIX}/bin/glo
	@rm ${PREFIX}/bin/xml2ass
	@rm ${PREFIX}/bin/vahb
