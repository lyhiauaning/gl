#!/bin/bash
while getopts ":v:a:o:" opt
do
    if [ $opt = 'v' ];then
    a=$OPTARG
    elif [ $opt = 'a' ];then
    a=$OPTARG
    elif [ $opt = 'o' ];then
    o=$OPTARG
    fi
done
mv $a GWJVSJBS2157.mp3
mv $v GWJVSJBS2157.mp4
ffmpeg -i GWJVSJBS2157.mp4 -i GWJVSJBS2157.mp3 -c:v copy -c:a aac -strict experimental GWJVSJBS2158.mp4
mv GWJVSJBS2158.mp4 $o
rm GWJVSJBS2157.mp3
rm GWJVSJBS2157.mp4
echo 输入：$a 和 $v
echo 输出：$o