echo '正在创建配置文件夹...'
mkdir $PREFIX/etc/gl
echo '完成!'
echo '正在解压安装文件...'
unzip $0
echo '完成!'
echo '正在进行配置配置文件...'
mv danmaku2ass $PREFIX/etc/gl
echo '1/2'
mv gl.conf $PREFIX/etc/gl
echo '1/2'
echo '完成!'
echo '正在配置shell脚本文件...'
mv gl $PREFIX/bin/gl
mv glo $PREFIX/bin/glo
mv xml2ass $PREFIX/bin/xml2ass
mv vahb $PREFIX/bin/vahb
echo '完成!'
echo '正在给予shell脚本文件执行权限...'
chmod a+x $PREFIX/bin/gl
echo '1/4'
chmod a+x $PREFIX/bin/glo
echo '2/4'
chmod a+x $PREFIX/bin/xml2ass
echo '3/4'
chmod a+x $PREFIX/bin/vahb
echo '4/4'
echo '完成!'
echo "正在安装依赖..."
apt update
if [[ ! -f "$PREFIX/bin/python" && -f "$PREFIX/bin/python3" ]];then
  apt install python -y 
  echo "正在安装依赖... 安装python成功！(用于执行python脚本)"
fi
if [[ ! -f "$PREFIX/bin/ffmpeg" ]];then
  apt install ffmpeg -y
  echo "正在安装依赖... 安装ffmpeg成功！(用于查看视频数据并输出json)"
fi
if [[ ! -f "$PREFIX/bin/jq" ]];then
  apt install jq -y 
  echo "正在安装依赖... 安装jq成功！(用于解析json)"
fi
echo '安装成功'
echo '您现在可以执行: "gl" 查看帮助'
exit 0
