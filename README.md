# From noob to 0day developer 

## Introduction 

the reason why I'm writting this kind of how-to become you into a exploit writer is because I had in the same boat as you , So I had to research link by link to find the right ones. I call this kind of how-to course from noob to hero covering the basics of penetration testing to the hottest topic such as Sandbox Escape. 

## The inspiration:

What has been kept me so interested and motivated into 0day research , and everything I googled led me to google security research team known as Google Project Zero. Don't judme maybe I cannot reach at that level yet, but the day I gave up on my dreams, I will be dead inside.


## Recommendations: 

* Aim for the impossible 
* This is not a basic course even if I call it "noob"
* Be prepared to suffer as much as possible 
* Nightmares
* Don't be afraid of assembly 
* Network with other cybersecurity folks
* Get familiar with WinDBG,Immunity , and IDA
* Don't be as those people who tell you "Try harder" (which in some cases means: I am not going to help you)

![bootcamp](https://github.com/SkyBulk/the-day-of-nightmares/blob/master/images/bootcamp.jpg)

## Information Gathering & Vulnerability Scanning
* [Netcat](https://www.computerhope.com/unix/nc.htm)
* [google hacking](https://www.exploit-db.com/google-hacking-database)	
* [Email Harvesting](https://spreadsecurity.github.io/2016/08/22/open-source-intelligence-with-theharvester.html)
* [Netcraft](https://searchdns.netcraft.com/)
* [whois](http://whois.domaintools.com/)
* [OSINT Framework](https://osintframework.com/)
* [Pipl Search](https://pipl.com/)
* [Shodan](https://www.shodan.io/)
* [DNSRecon](https://tools.kali.org/information-gathering/dnsrecon)
* [Gobuster](https://tools.kali.org/web-applications/gobuster)
* [Nikto](https://hackertarget.com/nikto-tutorial/)
* [Burp suite](https://media.licdn.com/dms/image/C4E12AQEehsOx8j6E7Q/article-inline_image-shrink_400_744/0?e=2127686400&v=beta&t=kLlvLj165J1I9PnXAB_PABR74x38qidzOWkOoNLncgI)
* [Hunter](https://hunter.io/)
* [Maltego](https://youtu.be/46st98FUf8s)
* [nmap](https://s3-us-west-2.amazonaws.com/stationx-public-download/nmap_cheet_sheet_0.6.pdf)

## Buffer Overflows

* [Exploit writing tutorial part 1 : Stack Based Overflows](https://www.corelan.be/index.php/2009/07/19/exploit-writing-tutorial-part-1-stack-based-overflows/)
* [Exploit writing tutorial part 2 : Stack Based Overflows – jumping to shellcode](https://www.corelan.be/index.php/2009/07/23/writing-buffer-overflow-exploits-a-quick-and-basic-tutorial-part-2/)
* [Part 1: Introduction to Exploit Development](https://www.fuzzysecurity.com/tutorials/expDev/1.html)
* [Part 2: Saved Return Pointer Overflows](https://www.fuzzysecurity.com/tutorials/expDev/2.html)
* [Finding Bad Characters with Immunity Debugger and Mona.py](https://bulbsecurity.com/finding-bad-characters-with-immunity-debugger-and-mona-py/)
* [Hunting bad characters with mona](https://github.com/codingo/OSCP-2/blob/master/Documents/Hunting%20bad%20characters%20with%20mona.pdf)

## Privilege Escalation

* [Windows Privilege Escalation Fundamentals](http://www.fuzzysecurity.com/tutorials/16.html)
* [Basic Linux Privilege Escalation](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
* [Privilege Escalation linux & windows](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_-_linux.html)

## Finding Public Exploits
* [Exploitdb](http://www.exploit-db.com/)
* [SecurityFocus](http://www.securityfocus.com/)

## Creating Metasploit Payloads

* [Payloads](https://netsec.ws/?p=331)


## Web Application Attacks

* [Cross Site Scripting (XSS)](https://www.owasp.org/index.php/Cross-site_Scripting_(XSS))
* [Stealing Cookies and Session Information](https://breakdev.org/sniping-insecure-cookies-with-xss/)
* [File Local Inclusion](https://highon.coffee/blog/lfi-cheat-sheet/)
* [Remote File Inclusion](https://securityxploded.com/remote-file-inclusion.php)
* [MySQL SQL Injection](http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet)


## Password Attacks
* [Cracking Passwords: 11 Password Attack Methods](https://datarecovery.com/rd/cracking-passwords-11-password-attack-methods-work/)
* [Hashkiller](https://hashkiller.co.uk/)
* [CrackStation](https://crackstation.net/)
* [Rule Based Attack](https://www.4armed.com/blog/hashcat-rule-based-attack/)

## Port Redirection and Tunneling

* [SSH Port Forwarding/Tunnelling](https://www.booleanworld.com/guide-ssh-port-forwarding-tunnelling/)
* [Introduction to pivoting, Part 1: SSH](https://blog.techorganic.com/2012/10/06/introduction-to-pivoting-part-1-ssh/)
* [Pivoting](https://www.ivoidwarranties.tech/posts/pentesting-tuts/pivoting/localport-forward/)
* [Explore Hidden Networks With Double Pivoting](https://pentest.blog/explore-hidden-networks-with-double-pivoting/)
* [A Red Teamer's guide to pivoting](https://artkond.com/2017/03/23/pivoting-guide/)

## Bypassing Antivirus Software

* [Veil](https://github.com/Veil-Framework/Veil)
* [Phantom-Evasion](https://github.com/oddcod3/Phantom-Evasion)
* [AV Bypass with Metasploit Templates and Custom Binaries](https://ired.team/offensive-security/av-bypass-with-metasploit-templates)

> At this point you will be able to perfom Penetration testing / Red Team stuff as an entry level 

> I didn't mention The Metasploit Framework, because I want you learn the TECHNIQUES 

![camp](https://github.com/SkyBulk/the-day-of-nightmares/blob/master/images/camp.jpg)

## Backdooring PE files

* [Backdooring PE File by Adding New Section Header](https://captmeelo.com/exploitdev/osceprep/2018/07/16/backdoor101-part1.html)
* [Backdooring PE-File (with ASLR)](https://hansesecure.de/backdooring-pe-file-with-aslr/)
* [Introduction to Manual Backdooring](https://www.exploit-db.com/docs/english/42061-introduction-to-manual-backdooring.pdf)

## Bypassing Antivirus Systems , the second stage 

* [Art of Anti Detection 1 – Introduction to AV & Detection Techniques](https://pentest.blog/art-of-anti-detection-1-introduction-to-av-detection-techniques/)
* [Art of Anti Detection 2 – PE Backdoor Manufacturing](https://pentest.blog/art-of-anti-detection-2-pe-backdoor-manufacturing/)

## Advanced Exploitation Techniques

> corelan 

* [Exploit writing tutorial part 1 : Stack Based Overflows](https://www.corelan.be/index.php/2009/07/19/exploit-writing-tutorial-part-1-stack-based-overflows/)
* [Exploit writing tutorial part 2 : Stack Based Overflows – jumping to shellcode](https://www.corelan.be/index.php/2009/07/23/writing-buffer-overflow-exploits-a-quick-and-basic-tutorial-part-2/)
* [Exploit writing tutorial part 3 : SEH Based Exploits](https://www.corelan.be/index.php/2009/07/25/writing-buffer-overflow-exploits-a-quick-and-basic-tutorial-part-3-seh/)
* [Exploit writing tutorial part 3b : SEH Based Exploits – just another example](https://www.corelan.be/index.php/2009/07/28/seh-based-exploit-writing-tutorial-continued-just-another-example-part-3b/)
* [Exploit writing tutorial part 4 : From Exploit to Metasploit – The basics](https://www.corelan.be/index.php/2009/08/12/exploit-writing-tutorials-part-4-from-exploit-to-metasploit-the-basics/)
* [Exploit writing tutorial part 5 : How debugger modules & plugins can speed up basic exploit development](https://www.corelan.be/index.php/2009/09/05/exploit-writing-tutorial-part-5-how-debugger-modules-plugins-can-speed-up-basic-exploit-development/)
* [Exploit writing tutorial part 6 : Bypassing Stack Cookies, SafeSeh, SEHOP, HW DEP and ASLR](https://www.corelan.be/index.php/2009/09/21/exploit-writing-tutorial-part-6-bypassing-stack-cookies-safeseh-hw-dep-and-aslr/)
* [Exploit writing tutorial part 8 : Win32 Egg Hunting](https://www.corelan.be/index.php/2010/01/09/exploit-writing-tutorial-part-8-win32-egg-hunting/)
* [Exploit writing tutorial part 9 : Introduction to Win32 shellcoding](https://www.corelan.be/index.php/2010/02/25/exploit-writing-tutorial-part-9-introduction-to-win32-shellcoding/)
* [Exploit writing tutorial part 10 : Chaining DEP with ROP – the Rubik’s[TM] Cube](https://www.corelan.be/index.php/2010/06/16/exploit-writing-tutorial-part-10-chaining-dep-with-rop-the-rubikstm-cube/)

> fuzzysecurity

* [Part 1: Introduction to Exploit Development](https://www.fuzzysecurity.com/tutorials/expDev/1.html)
* [Part 2: Saved Return Pointer Overflows](https://www.fuzzysecurity.com/tutorials/expDev/2.html)
* [Part 3: Structured Exception Handler (SEH)](http://www.fuzzysecurity.com/tutorials/expDev/3.html)
* [Part 4: Egg Hunters](http://www.fuzzysecurity.com/tutorials/expDev/4.html)
* [Part 6: Writing W32 shellcode](http://www.fuzzysecurity.com/tutorials/expDev/6.html)
* [Part 7: Return Oriented Programming](http://www.fuzzysecurity.com/tutorials/expDev/7.html)


## fuzzing

* [boofuzz](https://github.com/jtpereyda/boofuzz) -  A fork and successor of Sulley framework
* [Fuzzing with Peach Part 1](http://www.flinkd.org/fuzzing-with-peach-part-1/) - by Jason Kratzer of corelan team
* [Fuzzing with Peach Part 2](http://www.flinkd.org/fuzzing-with-peach-part-2-fixups-2/) - by Jason Kratzer of corelan team.
* [Win AFL](https://github.com/ivanfratric/winafl) - A fork of AFL for fuzzing Windows binaries by Ivan Fratic
* [Peach Fuzzer](https://sourceforge.net/projects/peachfuzz/) - Framework which helps to create custom dumb and smart fuzzers.
* [libFuzzer](http://llvm.org/docs/LibFuzzer.html) - In-process, coverage-guided, evolutionary fuzzing engine for targets written in C/C++.


## Debuggers  

* [Windbg](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools) - The preferred debugger by exploit writers.

* [Immunity Debugger](http://debugger.immunityinc.com) - Immunity Debugger by Immunity Sec.

* [Mona.py ( Plugin for windbg and Immunity dbg )](https://github.com/corelan/mona/) - Awesome tools that makes life easy for exploit developers.

* [GDB - Gnu Debugger](http://www.sourceware.org/gdb/) - The favorite linux debugger.

* [PEDA](https://github.com/longld/peda) - Python Exploit Development Assistance for GDB.



## Disassemblers 

*Dissemblers, disassembly frameworks etc.,*


[IDA Pro](https://www.hex-rays.com/products/ida/index.shtml) - The best disassembler



> At this point you will be confortable with intermediate exploit development from a somple BOF to bypass software protections such as DEP

> do an intensive reverse engineering course before jumping the third & last stage.  you will not know the light without it



## Heap Spraying

* [[https://www.fuzzysecurity.com/tutorials/expDev/8.html][Part 8: Spraying the Heap (Vanilla EIP)]] by FuzzySecurity
* [[https://www.fuzzysecurity.com/tutorials/expDev/11.html][Part 9: Spraying the Heap (Use-After-Free)]] by FuzzySecurity
* [[https://www.corelan.be/index.php/2013/02/19/deps-precise-heap-spray-on-firefox-and-ie10/][DEPS – Precise Heap Spray on Firefox and IE10]] by Corelan
* [[https://0x00sec.org/t/heap-exploitation-abusing-use-after-free/3580][Heap Exploitation ~ Abusing Use-After-Free]] by _py


## Heap Overflows

* [[http://www.fuzzysecurity.com/tutorials/mr_me/2.html][Heap Overflows For Humans 101]] by FuzzySecurity
* [[http://www.fuzzysecurity.com/tutorials/mr_me/3.html][Heap Overflows For Humans 102]] by FuzzySecurity
* [[http://www.fuzzysecurity.com/tutorials/mr_me/4.html][Heap Overflows For Humans 102.5]] by FuzzySecurity
* [[http://www.fuzzysecurity.com/tutorials/mr_me/5.html][Heap Overflows For Humans 103]] by FuzzySecurity
* [[http://www.fuzzysecurity.com/tutorials/mr_me/6.html][Heap Overflows For Humans 103.5]] by FuzzySecurity


## JIT-spray

* [Pointer inference and JIT-Spraying, Dion Blazakis, 2010](http://www.semantiscope.com/research/BHDC2010/BHDC-2010-Paper.pdf)
* [Writing JIT shellcode for fun and profit, Alexey Sintsov, 2010](http://dsecrg.com/files/pub/pdf/Writing%20JIT-Spray%20Shellcode%20for%20fun%20and%20profit.pdf)
 * [Too LeJIT to Quit: Extending JIT Spraying to ARM](http://www.internetsociety.org/sites/default/files/09_3_2.pdf)
* [Interpreter  Exploitation: Pointer Inference and JIT Spraying](http://www.semantiscope.com/research/BHDC2010/BHDC-2010-Paper.pdf)
* [Understanding JIT Spray](http://blog.cdleary.com/2011/08/understanding-jit-spray/)
* [Writing JIT-Spray Shellcode For Fun And Profit](https://packetstormsecurity.com/files/86975/Writing-JIT-Spray-Shellcode-For-Fun-And-Profit.html)
 * [The Devil is in the Constants: Bypassing Defenses in Browser JIT Engines](http://users.ics.forth.gr/~elathan/papers/ndss15.pdf)

## Browser

* [Beginners guide to UAT exploits IE 0day exploit development](https://0xicf.wordpress.com/2012/11/18/beginners-guide-to-use-after-free-exploits-ie-0-day-exploit-development/)
* [Fuzzy Security - Spraying the Heap [Chapter 1: Vanilla EIP] – Putting Needles in the Haystack](https://www.fuzzysecurity.com/tutorials/expDev/8.html)
* [Fuzzy Security - Spraying the Heap [Chapter 2: Use-After-Free] – Finding a needle in a Haystack](https://www.fuzzysecurity.com/tutorials/expDev/11.html)
* [Anatomy of an exploit – inside the CVE-2013-3893 Internet Explorer zero-day – Part 1](https://nakedsecurity.sophos.com/2013/10/11/anatomy-of-an-exploit-ie-zero-day-part-1/)
* [Using the JIT Vulnerability to Pwn Microsoft Edge](http://i.blackhat.com/asia-19/Fri-March-29/bh-asia-Li-Using-the-JIT-Vulnerability-to-Pwning-Microsoft-Edge.pdf)
* [Post-mortem Analysis of a Use-After-Free Vulnerability (CVE-2011-1260)](http://www.exploit-monday.com/2011/07/post-mortem-analysis-of-use-after-free_07.html)
* [Advanced Heapspraying Technique](https://www.owasp.org/images/0/01/OWASL_IL_2010_Jan_-_Moshe_Ben_Abu_-_Advanced_Heapspray.pdf)
* [HeapSpray Aurora Vulnerability](http://www.thegreycorner.com/2010/01/heap-spray-exploit-tutorial-internet.html)
* [Microsoft Edge Chakra JIT Type Confusion CVE-2019-0539](https://perception-point.io/resources/research/cve-2019-0539-exploitation/)
* [CVE-2019-0539 Root Cause Analysis](https://perception-point.io/resources/research/cve-2019-0539-root-cause-analysis/)
* [attacking javascript engines](http://www.phrack.org/papers/attacking_javascript_engines.html)
* [Learning browser exploitation via 33C3 CTF  feuerfuchs challenge](https://bruce30262.github.io/Learning-browser-exploitation-via-33C3-CTF-feuerfuchs-challenge/)
* [A Methodical Approach to Browser Exploitation](https://blog.ret2.io/2018/06/05/pwn2own-2018-exploit-development/)
* [Reducing target scope within JSC, building a JavaScript fuzzer](https://blog.ret2.io/2018/06/13/pwn2own-2018-vulnerability-discovery/)
* [Performing root-cause analysis of a JSC vulnerability](https://blog.ret2.io/2018/06/19/pwn2own-2018-root-cause-analysis/)
* [Weaponizing a JSC vulnerability for single-click RCE](https://blog.ret2.io/2018/07/11/pwn2own-2018-jsc-exploit/)
* [Evaluating the Safari sandbox, and fuzzing WindowServer on MacOS](https://blog.ret2.io/2018/07/25/pwn2own-2018-safari-sandbox/)
* [Weaponizing a Safari sandbox escape](https://blog.ret2.io/2018/08/28/pwn2own-2018-sandbox-escape/)
* [Microsoft Edge MemGC Internals](https://hitcon.org/2015/CMT/download/day2-h-r1.pdf)
* [The ECMA and the Chakra](http://conference.hitb.org/hitbsecconf2017ams/materials/CLOSING%20KEYNOTE%20-%20Natalie%20Silvanovich%20-%20The%20ECMA%20and%20The%20Chakra.pdf)
* [Memory Corruption Exploitation In Internet Explorer](https://www.syscan360.org/slides/2012_ZH_MemoryCorruptionExploitationInInternetExplorer_MotiJoseph.pdf)
* [IE 0day Analysis And Exploit](http://vdisk.weibo.com/s/dC_SSJ6Fvb71i)
* [Write Once, Pwn Anywhere](https://www.blackhat.com/docs/us-14/materials/us-14-Yu-Write-Once-Pwn-Anywhere.pdf)
* [The Art of Leaks: The Return of Heap Feng Shui](https://cansecwest.com/slides/2014/The%20Art%20of%20Leaks%20-%20read%20version%20-%20Yoyo.pdf)
* [IE 11 0day & Windows 8.1 Exploit](https://github.com/exp-sky/HitCon-2014-IE-11-0day-Windows-8.1-Exploit/blob/master/IE%2011%200day%20%26%20Windows%208.1%20Exploit.pdf)
* [IE11 Sandbox Escapes Presentation](https://www.blackhat.com/docs/us-14/materials/us-14-Forshaw-Digging-For_IE11-Sandbox-Escapes.pdf)
* [Spartan 0day & Exploit](https://github.com/exp-sky/HitCon-2015-spartan-0day-exploit)
* [Look Mom, I don't use Shellcode](https://www.syscan360.org/slides/2016_SH_Moritz_Jodeit_Look_Mom_I_Dont_Use_Shellcode.pdf)
* [Windows 10 x64 edge 0day and exploit](https://github.com/exp-sky/HitCon-2016-Windows-10-x64-edge-0day-and-exploit/blob/master/Windows%2010%20x64%20edge%200day%20and%20exploit.pdf)
* [1-Day Browser & Kernel Exploitation](http://powerofcommunity.net/poc2017/andrew.pdf)
* [The Secret of ChakraCore: 10 Ways to Go Beyond the Edge](http://conference.hitb.org/hitbsecconf2017ams/materials/D1T2%20-%20Linan%20Hao%20and%20Long%20Liu%20-%20The%20Secret%20of%20ChakraCore.pdf)
* [From Out of Memory to Remote Code Execution](https://speakerd.s3.amazonaws.com/presentations/c0a3e7bc0dca407cbafb465828ff204a/From_Out_of_Memory_to_Remote_Code_Execution_Yuki_Chen_PacSec2017_final.pdf)
* [Attacking WebKit Applications by exploiting memory corruption bugs](https://cansecwest.com/slides/2015/Liang_CanSecWest2015.pdf)
* [CVE-2018-5129: Out-of-bounds write with malformed IPC messages](https://infinite.loopsec.com.au/cve-2018-5129-how-i-found-my-first-cve)
* [it-sec catalog browser exploitation chapter](https://www.it-sec-catalog.info/browser_exploitation.html)
* [[https://phoenhex.re/2018-09-26/safari-array-concat][Exploiting a Safari information leak]] by Bruno Keith
* [[https://saelo.github.io/presentations/blackhat_us_18_attacking_client_side_jit_compilers.pdf][Attacking Client-Side JIT Compilers]] by Samuel Groß


## Enhanced Mitigation Experience Toolkit (EMET)
* [[https://www.offensive-security.com/vulndev/disarming-emet-v5-0/][Disarming EMET v5.0]] by Offensive Security
* [[https://www.offensive-security.com/vulndev/disarming-and-bypassing-emet-5-1/][Disarming and Bypassing EMET 5.1]] by Offensive Security
* [[https://www.offensive-security.com/vulndev/disarming-enhanced-mitigation-experience-toolkit-emet/][Disarming Enhanced Mitigation Experience Toolkit (EMET)]] by Offensive Security
* [[https://www.xorlab.com/blog/2016/10/27/emet-memprot-bypass/][Bypassing EMET 5.5 MemProt using VirtualAlloc]] by Matthias Ganz

## Mitigation Bypass
* [Disarming EMET v5.0](https://www.offensive-security.com/vulndev/disarming-emet-v5-0/)
* [Disarming and Bypassing EMET 5.1](https://www.offensive-security.com/vulndev/disarming-and-bypassing-emet-5-1/)
* [Universal DEP/ASLR bypass with msvcr71.dll and mona.py](https://www.corelan.be/index.php/2011/07/03/universal-depaslr-bypass-with-msvcr71-dll-and-mona-py/)
* [Chaining DEP with ROP – the Rubik’s[TM] Cube](https://www.corelan.be/index.php/2010/06/16/exploit-writing-tutorial-part-10-chaining-dep-with-rop-the-rubikstm-cube/)
* [Bypassing Stack Cookies, SafeSeh, SEHOP, HW DEP and ASLR](https://www.corelan.be/index.php/2009/09/21/exploit-writing-tutorial-part-6-bypassing-stack-cookies-safeseh-hw-dep-and-aslr/)
* [Development of a new Windows 10 KASLR Bypass (in One WinDBG Command)](https://www.offensive-security.com/vulndev/development-of-a-new-windows-10-kaslr-bypass-in-one-windbg-command/)
* [Disarming Enhanced Mitigation Experience Toolkit (EMET)](https://www.offensive-security.com/vulndev/disarming-enhanced-mitigation-experience-toolkit-emet/)
* [Simple EMET EAF bypass](http://casual-scrutiny.blogspot.com/2015/01/simple-emet-eaf-bypass.html)
* [Exploit Dev 101: Bypassing ASLR on Windows](https://www.abatchy.com/2017/06/exploit-dev-101-bypassing-aslr-on.html)
* [Bypassing Control Flow Guard in Windows 10](https://improsec.com/tech-blog/bypassing-control-flow-guard-in-windows-10)
* [Bypassing Control Flow Guard in Windows 10 - Part II](https://improsec.com/tech-blog/bypassing-control-flow-guard-on-windows-10-part-ii)
* [BYPASS CONTROL FLOW GUARD COMPREHENSIVELY](https://www.blackhat.com/docs/us-15/materials/us-15-Zhang-Bypass-Control-Flow-Guard-Comprehensively-wp.pdf)
* [CROSS THE WALL-BYPASS ALL MODERN MITIGATIONS OF MICROSOFT EDGE](https://www.blackhat.com/docs/asia-17/materials/asia-17-Li-Cross-The-Wall-Bypass-All-Modern-Mitigations-Of-Microsoft-Edge.pdf)
* [How to find the vulnerability to bypass the Control Flow Guard](https://cansecwest.com/slides/2017/CSW2017_HenryLi_How_to_find_the_vulnerability_to_bypass_the_ControlFlowGuard.pdf)
* [Bypassing Memory Mitigation Using Data-Only Exploitation Technique](https://conference.hitb.org/hitbsecconf2017ams/materials/D2T1%20-%20Bing%20Sun%20and%20Chong%20Xu%20-%20Bypassing%20Memory%20Mitigation%20Using%20Data-Only%20Exploitation%20Techniques.pdf)
* [CHAKRA JIT CFG BYPASS](https://theori.io/research/chakra-jit-cfg-bypass)
* [SMEP: What is it, and how to beat it on Windows](https://j00ru.vexillium.org/2011/06/smep-what-is-it-and-how-to-beat-it-on-windows/)
* [ROP for SMEP bypass](https://rstforums.com/forum/topic/106553-rop-for-smep-bypass/)
* [Smashing The Browser](https://github.com/demi6od/Smashing_The_Browser)
* [Browser security mitigations against memory corruption vulnerabilities](https://docs.google.com/document/d/19dspgrz35VoJwdWOboENZvccTSGudjQ_p8J4OPsYztM/edit)
