#!/bin/bash
echo $1
if [[ "$#" > "0" ]];then
  if [[ "$1" == "--all" || "$1" == "-a" ]];then
    ls $2/*.xml | xargs -n 1 -d '\n' xml2ass
  else
    for i in "$@"
    do
      echo $i
      if [[ -f "${i%.cmt.xml*}.mp4" && -f "${i%.xml*}.mp4" ]];then
        videodate=`fprobe -select_streams v -show_entries format=duration,size,bit_rate,filename -show_streams -v quiet -of csv="p=0" -of json -i "$i"`
        videowidth=`jq -r '.streams[].width' $videodate`
        videoheight=`jq -r '.streams[].height' $videodate`
      else
        videowidth=1920
        videoheight=1080
      fi
      if expr "$i" : ".*\.cmt\.xml" &> /dev/null ;then
        python $PREFIX/etc/gl/danmaku2ass.py -o "${i%.cmt.xml*}.ass" -s ${videowidth}x${videoheight} -fn "Microsoft Yahei" -fs 48 -a 0.8 -dm 14 -ds 6 "$i"
      elif expr "$i" : ".*\.xml" &> /dev/null ;then
        python $PREFIX/etc/gl/danmaku2ass.py -o "${i%.xml*}.ass" -s ${videowidth}x${videoheight} -fn "Microsoft Yahei" -fs 48 -a 0.8 -dm 14 -ds 6 "$i"
      fi
    done
  fi
else
  ls ./*.xml | xargs -n 1 -d '\n' xml2ass
fi