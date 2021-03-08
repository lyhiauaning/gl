#!/bin/bash
if expr "$1" : ".*\.cmt\.xml" &>/dev/null ;then
  python $PREFIX/etc/gl/danmaku2ass.py -o "${1%.cmt.xml*}.ass" -s 1920x1080 -fn "Microsoft Yahei" -fs 48 -a 0.8 -dm 14 -ds 6 "$1"
elif expr "$1" : ".*\.xml" &>/dev/null ;then
  python $PREFIX/etc/gl/danmaku2ass.py -o "${1%.xml*}.ass" -s 1920x1080 -fn "Microsoft Yahei" -fs 48 -a 0.8 -dm 14 -ds 6 "$1"
fi
