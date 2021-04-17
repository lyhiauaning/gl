#!/bin/bash
if [[ "$#" > "1" ]];then
  if [[ "$1" == "--all" || "$1" == "-a" ]];then
    ls $2/*.xml | xargs -n 1 -d '\n' xml2ass
  else
    for i in $@
    do
      if expr "$i" : ".*\.cmt\.xml" &> /dev/null ;then
        python $PREFIX/etc/gl/danmaku2ass.py -o "${i%.cmt.xml*}.ass" -s 1920x1080 -fn "Microsoft Yahei" -fs 48 -a 0.8 -dm 14 -ds 6 "$i"
      elif expr "$i" : ".*\.xml" &> /dev/null ;then
        python $PREFIX/etc/gl/danmaku2ass.py -o "${i%.xml*}.ass" -s 1920x1080 -fn "Microsoft Yahei" -fs 48 -a 0.8 -dm 14 -ds 6 "$i"
      fi
    done
  fi
else
  ls ./*.xml | xargs -n 1 -d '\n' xml2ass
fi