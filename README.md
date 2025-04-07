# UnwantedBlocker
This is some program i made because one of contributors on my friend server made program named [MalwareGuard](https://github.com/0xresetti/malwareguard) and i noticed the detection of program being ran is very slow it takes more than a second to detect program has started and in this time already something can be send to attacker
## So what's the solution?
I actually don't know but i asked chatgpt! and i got straight answer that i should inject dll to any app and it captures createprocessw that will create process! it stops that and asks through a pipe a controller that will show messagebox if you want to run that. The injector injects dll and starts 2 instances of controller one is elevated one not. elevated controller controls dll in elevated processes, and not elevated you know alr.

The injector every 700ms checks if cmd, powershell, explorer processes have injected dll already if not it injects the dll into it
## Did it took me long to make it?
more than a day idk and yes i used chatgpt but it was stupid it said it fixed smth and didn't do anything actually. The injector code is mostly made by me because i know c#.

## How to build it?
Firstly build dll, controller, startasnonadmin2

**Make sure the executables are single file (for startasnonadmin publish it with single file configuration). For anything else just use visual studio because its set up already. If it's too hard for you use already built binary**

Then copy all files you just built to the injector directory and build it. MAKE SURE DLL AND ALL EXECUTABLES ARE SET AS EMBEDDED RESOURCE. MAKE SURE ITS NAMED MAIN.DLL, FANUMTAX.EXE, STARTASNONADMIN.EXE

### Im sorry for every mistake or smth i made wrongly there but this is my first c++ project PLS UNDERSTAND😭
