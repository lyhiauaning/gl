#!/bin/bash
clear
logo (){
echo -e '\n'
echo 'ヾ(≧O≦)〃嗷~恭喜你发现镇店之宝'
echo -e '\n'
}
home0 (){
echo -e "\n\n\n\n\n"
sleep 0.016
echo "            001           安装when"
sleep 0.016
echo "            002           获取存储权限"
sleep 0.016
echo "            003           修改问候语放"
sleep 0.016
echo "            004           安装wget下载工具"
sleep 0.016
echo "            005           换源"
sleep 0.016
echo "            006           添加shell脚本为命令"
sleep 0.016
echo "            007           更新gl"
sleep 0.016
echo "            008           其他"
sleep 0.016
echo "            009           初始化"
sleep 0.016
#echo "            010           Termux-API帮助"
#sleep 0.016
echo -e "\n                                       0             退出"
sleep 0.016
echo -e "                                       00            退出"
sleep 0.016
echo -e "                                       01            查看作者网站"
sleep 0.016
echo -e "                                       uninstall     卸载gl"
read -p 'gl~> ' cmd
case $cmd in
00)
clear
sleep 0.016
cat $PREFIX/etc/motd
exit;;
01)
  termux-open-url https://han.gulanguage.cn/
  echo '地址：han.gulanguage.cn';;
0)
clear
sleep 0.016
cat $PREFIX/etc/motd
exit;;
001)
apt update
apt upgrade
echo "deb [trusted=yes] https://nibazshab.github.io/404/sourc/ termux extras" >> $PREFIX/etc/apt/sources.list; pkg in when
home0;;
002)
termux-setup-storage
clear
sleep 0.016
home0;;
003)
sed -i '1,$d' $PREFIX/etc/motd;
echo '欢迎回来呢~主银~
あなたが好き！' >> $PREFIX/etc/motd
echo '修改完成！'
sleep 1
clear
home0;;
004)
apt update
apt upgrade
pkg install wget
home0;;
005)
home1;;
006)
home2;;
007)
update
  home0;;
008)
  home3;;
009)
  home4;;
music)
  music;;
#010)python $PREFIX/etc/gl/termux-api-command.py;;
uninstall)
  ungl;;
*)
echo '啊这，主人，好像没有这个选项诶！Ծ ̮ Ծ'
sleep 1
clear
home0;;
esac
}

home1 (){
clear
sleep 0.5
echo -e "\n\n\n\n\n"
echo "            0           返回"
sleep 0.016
echo "            1           清华源"
sleep 0.016
echo "            2           淘宝源"
sleep 0.016
echo -e '\n                                       00            退出'
read -p 'gl~> ' cmd2
case $cmd2 in
00)
clear
sleep 0.016
cat $PREFIX/etc/motd;;
0)
clear
home0;;
1)
sed -i 's@^\(deb.*stable main\)$@#\1\ndeb https://mirrors.tuna.tsinghua.edu.cn/termux-packages-24 stable main@' $PREFIX/etc/apt/sources.list
home1;;
2)
echo '那个，还不行啦~'
sleep 1
home1;;
*)
echo '啊那个，主人，你是不是输错了⚆_⚆？'
sleep 1
home1;;
esac
}

home2 (){
clear
sleep 0.5
echo "            0           返回"
sleep 0.016
echo "                        其他："
sleep 0.016
echo "                        文件名：需要做为命令的脚本名，带后缀"
sleep 0.016
echo "                        命令名：启动该脚本的命令"
sleep 0.016
echo -e '\n                                       00            退出'
read -p '请输入文件名或者对应数字：' cmd3
case $cmd3 in
00)
clear
sleep 0.016
cat $PREFIX/etc/motd;;
0)
clear
home0;;
*)
read -p '请输入命令名' name
mv $cmd3 $PREFIX/bin/$name
chmod +x $PREFIX/bin/$name
echo '完成'
sleep 1
home2;;
esac
}

home3 (){
clear
sleep 0.5
echo -e "\n\n\n\n\n"
echo '            0            返回'
sleep 0.016
echo '            1            下载我的世界'
sleep 0.016
echo '            2            底部小键盘1'
sleep 0.016
echo '            3            安装cmus音乐播放器'
sleep 0.016
echo '            4            底部小键盘2'
sleep 0.016
echo '            5            视频&音频合并'
sleep 0.016
echo '            6            xml弹幕转ass'
sleep 0.016
echo -e '\n                                       00            退出'
read -p 'gl~> ' cmd4
case $cmd4 in
00)
clear
sleep 0.016
cat $PREFIX/etc/motd;;
0)
clear
home0;;
1)
echo -e "\n\n\n\n"
echo '我还没做呢，等待更新吧！'
sleep 1
home3;;
2)
echo "extra-keys = [['\"','=','+','.',',','|','?'],['ALT','{','<','&','>','}','BACKSLASH'],['TAB','#','-','~','/','*','$'],['ESC','(','HOME','UP','END',')','PGUP'],['CTRL','[','LEFT','DOWN','RIGHT',']','PGDN']]" > ~/.termux/termux.properties
termux-reload-settings
echo '修改完成,可能被压缩键盘,需要重启'
sleep 1
home3;;
3)
pkg in cmus
home3;;
4)
echo "extra-keys = [['\`','!','@','#','$','%','^','&','*','(',')','_','+'],['ESC','1','2','3','4','5','6','7','8','9','0','-','='],['TAB','q','w','e','r','t','y','u','i','o','p','[',']'],['ALT','a','s','d','f','g','h','i','j','k','l',';','APOSTROPHE'],['INS','CTRL','z','x','c','v','b','n','m',',','.','/','ENTER'],['HOME','ls','ll','cd ','vim ','END',' ','DEL','LEFT','DOWN','UP','RIGHT','BKSP'],['find ','Q','W','E','R','T','Y','U','I','O','P','{','}'],['--','A','S','D','F','G','H','J','K','L',':','QUOTE','cd /'],['FN','Z','X','C','V','B','N','M','<','>','?','cd ..','cd ~'],['~','F1','F2','F3','F4','F5','F6','F7','F8','F9','F10','F11','F12']]" > ~/.termux/termux.properties
termux-reload-settings
echo '修改完成,可能被压缩键盘,需要重启'
sleep 1
home3;;
5)
echo -e '需要事先安装ffmpeg，安装命令pkg install ffmpeg\n输入视频文件格式必须为MP4，音频文件必须为MP3'
read -p 'gl~> 视频文件名> ' video
sleep 0.016
read -p 'gl~> 音频文件名> ' aideo
sleep 0.016
read -p 'gl~> 输出视频名> ' output
sleep 0.016
echo -e '请确认文件：输入视频：'$video'\n 输入音频：'$aideo'\n输出视频：'$output
read -p 'gl~> 回车继续执行' cmd5
case cmd5 in
*)
mv $video video.mp4
mv $aideo aideo.mp3
ffmpeg -i video.mp4 -i audio.mp3 -c:v copy -c:a aac -strict experimental output.mp4
mv output.mp4 $output
rm video.mp4
rm aideo.mp3
echo '合并成功！'
sleep 1
clear;;
0)
clear;;
00)
exit;;
esac
home3;;
6)
read -p 'gl~> 请输入xml文件名> ' xml
read -p 'gl~> 请输入输出ass文件名> ' ass
case xml in
*)
mv $xml index.xml
python $PREFIX/etc/gl/danmaku2ass.py -o ./index.ass -s 1920x1080 -fn "Microsoft Yahei" -fs 48 -a 0.8 -dm 14 -ds 6 ./index.xml
mv index.ass $ass
rm index.xml
echo '转化完成!'
sleep 1
clear;;
esac
sleep 1
clear
home3;;
*)
  echo '你是有多笨呢，这都能输错呀！'
  sleep 1
  home3;;
esac
}

home4 (){
echo '正在初始化中......'
sleep 0.5
echo '安装openssh中'
pkg install openssh
echo '安装openssh完成'
sleep 0.5
echo '安装vim中......'
sleep 0.5
pkg install vim
echo '安装vim完成'
sleep 0.5
echo '安装cmus中......'
pkg in cmus
echo '安装cmus完成'
sleep 1
home0
}

music (){
logo;
echo '            0            返回'
sleep 0.016
echo '            1~9         音乐编号'
sleep 0.016
echo -e '\n                                       00            退出'
read -p "gl~> " cmd
case $cmd in
00)
clear
sleep 0.016
cat $PREFIX/etc/motd;;
0)
clear
home0;;
1)
play -t mp3 "http://api.funs.ml/lzy/api.php?url=i49NLjb46di&type=down";;
2)
play -t mp3 "http://api.funs.ml/lzy/api.php?url=icWcrjb46fa&type=down";;
3)
play -t mp3 "http://api.funs.ml/lzy/api.php?url=iEkVgjb46lg&type=down";;
4)
play -t mp3 "http://api.funs.ml/lzy/api.php?url=iLMoFjb46pa&type=down";;
5)
play -t mp3 "http://api.funs.ml/lzy/api.php?url=iENO9jb46te&type=down";;
6)
play -t mp3 "http://api.funs.ml/lzy/api.php?url=iJHuljb46za&type=down";;
7)
play -t mp3 "http://api.funs.ml/lzy/api.php?url=i3VN2jb470b&type=down";;
8)
play -t mp3 "http://api.funs.ml/lzy/api.php?url=iGxZgjb471c&type=down";;
9)
play -t mp3 "http://api.funs.ml/lzy/api.php?url=iIzgzjb472d&type=down";;
*)
echo "错误或你未输入，可以输入1~9！";
music;;
esac
}

ungl (){
rm -r $PREFIX/etc/gl
rm $PREFIX/bin/gl
rm $PREFIX/bin/glo
rm $PREFIX/bin/xml2ass
rm $PREFIX/bin/vahb
}

update (){
wget https://gl.gulanguage.cn/code/gl.conf
wget https://gl.gulanguage.cn/code/gl.sh
wget https://gl.gulanguage.cn/code/gl-old.sh
wget https://gl.gulanguage.cn/code/xml2ass.sh
wget https://gl.gulanguage.cn/code/vahb.sh
wget https://gl.gulanguage.cn/code/danmaku2ass.py
wget https://gl.gulanguage.cn/code/termux-api-command.py
mkdir $PREFIX/etc/gl/
mv gl.conf $PREFIX/etc/gl/
mv danmaku2ass.py $PREFIX/etc/gl/
mv termux-api-command.py $PREFIX/etc/gl/
mv gl.sh $PREFIX/bin/gl
mv gl-old.sh $PREFIX/bin/glo
mv xml2ass.sh $PREFIX/bin/xml2ass
mv vahb.sh $PREFIX/bin/vahb
chmod +x $PREFIX/bin/gl
chmod +x $PREFIX/bin/glo
chmod +x $PREFIX/bin/xml2ass
chmod +x $PREFIX/bin/vahb
echo '更新完成'
sleep 1
clear
}

logo;
home0;
