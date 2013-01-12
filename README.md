=====Linux=====

Catcher - http packet viewer for linux. Written in C#, requires mono (>= 2.8). 
Uses SharpPcap library, you need to have >= libpcap0.8 installed too. Although it may work with lower versions too.
Run from binaries folder with root privileges: 'sudo mono catcher.exe', until I (or you) figure out how to sniff without root. 

Unlike fiddler and like wireshark catcher doesn't act as proxy: no packets go through it, 
instead it passively captures tcp packets flying by and tries to assemble http data. 
The problem with this is some packets are going to be lost even when capture is handled correctly.
Another problem is difficulty to decrypt SSL packets (man in the middle is not applicable). 
But it seem to work fine with small/medium sized http data (<= 2 Mb or so) and on a bright side you see all
http packets travelling through selected interface and not just from a given application.
If you want to catch packets going through localhost or 127.0.0.1 select loopback interface from devices menu.

The source project created in MonoDevelop 3.0.5.


====Windows====

It turns out it works on windows! You'll need .net 4.0, gtk# for .net (http://www.go-mono.com/mono-downloads/download.html) and
winpcap library (http://www.winpcap.org/). Once these installed run catcher.exe from windows_binaries folder.

Source project is opened by visual studio flawlessly.


====Mac====

Should work on a mac in theory, although I haven't tried that. Steps:
*get libpcap
*get mono and gtk# for mac
*get monodevelop for mac
*get sources from here and open it in monodevelop
*compile
*it should work (maybe with sudo) 


Please give feedback here on github or at http://rextester.com/feedback (questions are welcome too).

![catcher on ubuntu](https://raw.github.com/ren85/catcher/master/catcher.png)

