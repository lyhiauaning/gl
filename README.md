# 介绍  
* 名称：gl  
* 制作本工具的原因：方便本人自己的使用  
## 使用方法  
* 安装：  
```
make  
```
* 使用：  
```sh
gl  #查看帮助  
glo  #旧版菜单  
vahb [-a] [input audio file] [-v] [input video file] [-o] [output file]  #合并视频和音频  
xml2ass：  
    xml2ass [file]  #转换[file]为ass  
    xml2ass [--all | -a] [directory]  #转换[directory]下的所有xml弹幕  
    xml2ass [directory]/*.xml #转换[directory]下的所有xml弹幕  
    xml2ass *.xml  #转换当前目录下所有xml弹幕  
```
# 其他：  
* 编译：  
  * termux
```sh
make encode  
make
```
