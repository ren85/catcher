Catcher - http packet viewer for linux. Written in C#, requires mono (>= 2.8). Uses SharpPcap library.
Run with root privileges: 'sudo mono catcher.exe', until I (or you) figure out how to sniff without root. 
Also in params.txt file you need to specify a number of device to sniff on. Devices are listed by 'ifconfig' command.
Still have bugs and issues, particularly not supporting SSL.

Unlike similar tools catcher doesn't act as proxy: no packets go through it, instead it passively captures tcp packets flying by 
and tries to assemble http data. The problem with this is some packets are going to be lost even when capture is handled correctly.
Another problem is difficulty to decrypt SSL packets (man in the middle is not applicable). But it seem to work fine with small/medium
sized http data (<= 2 Mb or so).

The source project created in MonoDevelop 3.0.5.
