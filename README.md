# SafeExamBrowser Exploit

## !!DISCLAIMER!!
**This project is created for educational purposes ONLY! It is made as an intention to help devs and security researchers understand software security in things like memory injection and how "managed" apps (like those built on .net) can be modified at runtime. it MUST NOT be used to violate any terms of service, be used for cheating or any other actions that go against any rules. All actions are the responsibility of the user and I (as the author and programmer) DO NOT take any responsibility for what happens after.**


This exploit works by injecting a dll into seb’s process to modify its behavior and bypass some major security restrictions and add extra features.

### Features of this exploit:

#### 1. **Automated and persistent**

It attaches itself to seb and injects the custom dll into it the moment it opens and if the browser is closed and reopened, it will still automatically reapply all modifications at runtime... it is also coded to add itself to startup for persistence but if you don't want this to happen you can either turn it off from startup settings or if you're a little nerdy you can modify the code to not set it up in the first place (the code is fully commented and I tried my best to assume newcomers so check it out)

#### 2. **Kiosk Mode**

It automatically sets the mode to use 'DisableExplorerShell' at initialization by forcefully making it use our method instead of the original one... also it doesn't patch it if the value that was set in config is 'none' to better not look obvious cause 'none' and 'DisableExplorershell' have a lot of ui differences that will give it away also it's not needed to patch if it's already set to 'none' in config. explanation are more in the doc.

#### 3. **Policy modification**

It disables several of its main security policies:

* Clipboard: enables copy-paste functionality, which is disabled by default to prevent cheating.
* VM support: bypasses the check that prevents the browser from running inside a vm AND it sometimes uses this vm detection as a way to 'stop' a patched dll but this is a false-positive thing, it doesnt matter cause 1. it happens rarely, 2. we're patching it at runtime and no code on disk is touched.
* App whitelisting and blacklisting: adds 3rd party apps (edge is included because it's on all windows computers and i thought it would be a good idea over chrome for compatibility) to seb's "allowed" list so they aren't force closed and also removes all blacklisted apps once it's loaded from the config (this (clearing blacklisted app) isn't necessary and not the main goal either so it's up to you)

#### 4. **Security evasion**

The hardest thing about dll injections is that they are easy to detect and get blocked even by basic AVs and windows defender and I tried my best by implementing:

* AV evasion: uses data scrambling (xor encryption) to hide its main 'purpose' from win defender and other av.
* Function: are uncommon and 'advanced system' techniques to load its code into seb's memory without creating suspicious new "tasks" that security monitors look for.... and for the most part this should make it evade most AVs (at least basic ones) but if not feel free to allow it from threat or turn it off entirely (not recommended).

## What makes this different from others?

Great question, even if I'm the one who asked myself I'm sure this is what most people will ask and the answer is it's "fully cracked" and what i mean by that is ALMOST all (including some paid ones) do a static patch which affects the final BEK (browser exam key) hash which gets validated by the server to verify if the user's seb is original and to be honest for a small exam yeah you can use it but for high stake exams it DOES NOT and WILL NOT work and this exploit is runtime based which bypasses the static code verification giving the same BEK and config key as the original one
<img width="3143" height="902" alt="bek_ss" src="https://github.com/user-attachments/assets/376d5246-5fd0-4d69-969c-70e2872b791f" />

The second thing is it's almost the same as the look of the original seb taht setup with the same config. I see in a lot of modded versions it's so obvious that it's not even worth paying lol but aside from the joke it's not going to 'fool' anyone and that's why i chose 'DisableExplorerShell' instead of 'none' in the first place to patch the logic and make the ui exactly the same as the original one.

The third is it's ALMOST not patchable since all the script is doing is using its own functionality against it... and that's the scariest part, you can't do anything about it unless making it harder by implementing things like runtime validation to check if it's getting altered at runtime and even then it's still bypassable.

Anyway, the fourth one is that it's open source and has its own documentation (feel free to read it, you will gain more understanding on what I'm saying) and the last one is it's the 'only' free fully working exploit you can find out there.

# Download/Usage

Download the zip file from the release and extract it, move the folder to somewhere safe and open the folder and finally run 'RunMe.exe' with administrator permission

=> To use the third party app, which is microsoft edge in our case, the hotkey is left ctrl+shift to launch it as a topmost window.

**NOTE**: admin permission is NEEDED to allow access and write seb's memory. For more info see 'SEBeXDoc.pdf'
