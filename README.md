# gta5-extended-video-export-2

A WIP upgrade of Extended Video Export for GTA V. (original can be found [here](https://github.com/ali-alidoust/gta5-extended-video-export), all credit goes to ali-alidoust).

## Requirements

* [C++ ScriptHook by Alexander Blade](http://www.dev-c.com/gtav/scripthookv/)
* [vcpkg](https://vcpkg.io/)

## vcpkg Package Requirements.

* DirectXTex
* PolyHook2
* OpenEXR 3.0
* zlib
* YARA
* ffmpeg

## Contributing

You'll need Visual Studio ~~2015~~ 2019 or higher to open the project file and the [Script Hook V SDK](http://www.dev-c.com/gtav/scripthookv/) extracted into "[/gta5-extended-video-export](/gta5-extended-video-export)".

In addition, packages must be installed through vcpkg due to NuGet not having the newest versions of the packages listed above.

```
vcpkg install directxtex[openexr]:x64-windows
vcpkg install polyhook2:x64-windows
vcpkg install zlib:x64-windows
vcpkg install yara:x64-windows
vcpkg install ffmpeg[core,zlib,xml2,x265,x264,webp,vpx,vorbis,version3,swresample,swscale,speex,soxr,snappy,sdl2,opus,postproc,openjpeg,opengl,opencl,nvcodec,mp3lame,lzma,ilbc,iconv,gpl,freetype,fribidi,fontconfig,ffprobe,ffmpeg,fdk-aac,dav1d,avresample,avformat,avfilter,avcodec,aom]:x64-windows
```

Contributions to the project are welcome. Please use GitHub [pull requests](https://help.github.com/articles/using-pull-requests/).

