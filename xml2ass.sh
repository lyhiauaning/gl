#!/bin/bash
while getopts ":i:o:" opt
do
    if [ $opt = 'i' ];then
    i=$OPTARG
    elif [ $opt = 'o' ];then
    o=$OPTARG
    fi
done
python ~/.gl/danmaku2ass.py -o "$o" -s 1920x1080 -fn "Microsoft Yahei" -fs 48 -a 0.8 -dm 14 -ds 6 "$i"
echo 输入：$i
echo 输出：$o