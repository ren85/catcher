=====Linux=====

Catcher - http packet viewer for linux. Written in C#, requires mono (>= 2.8). 
Uses SharpPcap library, you need to have >= libpcap0.8 and libpcap0.8-dev installed too.
Run from binaries folder with root privileges: 'sudo mono catcher.exe', until I (or you) figure out how to sniff without root. 

Unlike similar tools catcher doesn't act as proxy: no packets go through it, instead it passively captures tcp packets flying by 
and tries to assemble http data. The problem with this is some packets are going to be lost even when capture is handled correctly.
Another problem is difficulty to decrypt SSL packets (man in the middle is not applicable). But it seem to work fine with small/medium
sized http data (<= 2 Mb or so).

The source project created in MonoDevelop 3.0.5.


====Windows====

It turns out it works on windows! You'll .net 4.0, gtk# for .net (http://www.go-mono.com/mono-downloads/download.html) and
winpcap library (http://www.winpcap.org/). Once these installed run catcher.exe from windows_binaries folder.

Source project is opened by visual studio flawlessly.
