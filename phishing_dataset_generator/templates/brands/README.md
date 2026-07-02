# Brand Login Page Templates

## How to add a brand template

1. Visit the brand's real login page (e.g., `https://accounts.google.com`)
2. Save the full HTML (browser DevTools → Elements → right-click → Copy → Copy outerHTML)
3. Create a file here named `<brand>.html` (e.g., `google.html`)
4. Edit the HTML and add these placeholders where appropriate:

### Required placeholders

| Placeholder | Where | Purpose |
|---|---|---|
| `{{FORM_ACTION}}` | In the `<form action="...">` tag | Generator replaces with phishing or legitimate URL |
| `{{HIDDEN_FIELDS}}` | Inside the `<form>`, before the submit button | Generator injects hidden tracking fields |
| `{{PLATFORM_URL}}` | Anywhere you want the hosting domain to appear | Replaced with e.g. `auth-verify.github.io` |

### Example

In your saved Google login HTML, find the form tag:
```html
<form action="https://accounts.google.com/signin/v2/challenge/pwd" method="POST">
```

Replace it with:
```html
<form action="{{FORM_ACTION}}" method="POST">
    {{HIDDEN_FIELDS}}
```

### What the generator does

**Phishing version:**
- `{{FORM_ACTION}}` → `https://auth-verify.github.io/collect` (or netlify.app, vercel.app, etc.)
- `{{HIDDEN_FIELDS}}` → 1-4 hidden `<input>` fields for tracking/exfiltration

**Legitimate version:**
- `{{FORM_ACTION}}` → `https://accounts.google.com/signin` (the real domain)
- `{{HIDDEN_FIELDS}}` → empty (or a CSRF token)

### Tips

- You don't need to include every single asset (images, fonts) — the structural HTML and inline styles are what matter
- If the login page uses external CSS/JS, you can inline the critical styles or leave them as `<link>` tags
- The goal is structural fidelity — the page should look like the real login flow
- You can simplify dynamic parts (React/Angular components) to static HTML as long as the layout stays the same
