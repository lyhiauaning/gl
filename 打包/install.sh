lines=36
echo '正在创建配置文件夹...'
mkdir ~/.gl
echo '完成!'
echo '正在解压安装文件...'
unzip $0
echo '完成!'
echo '正在进行配置配置文件...'
mv danmaku2ass.py ~/.gl/
echo '1/3'
mv termux-api-command.py ~/.gl/
echo '2/3'
#mv xml2ass.sh ~/.gl/
mv config.gl ~/.gl/
echo '3/3'
echo '完成!'
echo '正在配置shell脚本文件'
mv gl.sh $PREFIX/bin/gl
mv gl-old.sh $PREFIX/bin/glo
mv xml2ass.sh $PREFIX/bin/xml2ass
mv vahb.sh $PREFIX/bin/vahb
echo '完成!'
echo '正在给予shell脚本文件执行权限'
chmod a+x $PREFIX/bin/gl
echo '1/4'
chmod a+x $PREFIX/bin/glo
echo '2/4'
chmod a+x $PREFIX/bin/xml2ass
echo '3/4'
chmod a+x $PREFIX/bin/vahb
echo '4/4'
echo '完成!'
echo '安装成功'
echo '您现在可以执行: gl 查看帮助'
exit 0
