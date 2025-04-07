# UnwantedBlocker
This is some program i made because one of contributors on my friend server made program named [MalwareGuard](https://github.com/0xresetti/malwareguard) and i noticed the detection of program being ran is very slow it takes more than a second to detect program has started and in this time already something can be send to attacker
## So what's the solution?
I actually don't know but i asked chatgpt! and i got straight answer that i should inject dll to any app and it captures createprocessw that will create process! it stops that and asks through a pipe a controller that will show messagebox if you want to run that. The injector injects dll and starts 2 instances of controller one is elevated one not. elevated controller controls dll in elevated processes, and not elevated you know alr.

The injector every 700ms checks if cmd, powershell, explorer processes have injected dll already if not it injects the dll into it
## Did it took me long to make it?
more than a day idk and yes i used chatgpt but it was stupid it said it fixed smth and didn't do anything actually. The injector code is mostly made by me because i know c#.

### Im sorry for every mistake or smth i made wrongly there but this is my first c++ project PLS UNDERSTAND😭
