> ⚠️ **Status: untested.** This extension is provided as-is and has **not been tested in production**. Please feel free to fork, modify, improve, and open pull requests.
>
> Licensed under **GNU GPLv3** (see [LICENSE](LICENSE)).

# IP Block Protection -- PrestaShop module

Screens front-office visitors against the [ip-block.com](https://www.ip-block.com)
IP-screening service and blocks flagged IP addresses. Built and verified against
**PrestaShop 9.1.4** (also compatible with PrestaShop 1.7 / 8.x).

## What it does

* Runs as early as possible on storefront requests via the `actionDispatcherBefore`
  hook (before the front controller executes).
* Determines the real client IP (optionally from `CF-Connecting-IP` / `X-Forwarded-For`).
* Sends `POST https://api.ip-block.com/v1/check` with a 1 second timeout.
* Blocks the visitor **only** when the API returns `{"action":"block"}`.
* On any error/timeout/non-2xx response it applies the fail mode
  (default **fail open** = allow).
* Caches each decision (default 300s) keyed by `md5(ip|user_agent|referrer)`
  using PrestaShop's native cache.
* **Never** screens the back office, so you cannot be locked out of PrestaShop.
* Always honours the whitelist.

## Install

1. Copy the `modules/ipblockprotection/` folder into your PrestaShop
   `modules/` directory (or zip that folder and upload it via
   **Modules > Module Manager > Upload a module**).
2. Find **IP Block Protection** in the Module Manager and click **Install**.
3. Click **Configure**.

## Configure

| Setting            | Purpose                                                             |
|--------------------|---------------------------------------------------------------------|
| Enable protection  | Master on/off switch.                                                |
| Site ID            | Your ip-block.com site identifier.                                   |
| API key            | Your ip-block.com API key (sent in the request body).               |
| API URL            | Endpoint. Default `https://api.ip-block.com/v1/check`.              |
| Fail open          | On API failure: Yes = allow (default), No = block.                  |
| Cache TTL          | Seconds to cache a decision. `0` = check on every request. Default 300. |
| Behind a proxy/CDN | Read real IP from `CF-Connecting-IP` / `X-Forwarded-For`.           |
| Block action       | `redirect` (default) to the blocked page, or `message` (HTTP 403).  |
| Block message      | Text shown when Block action = message.                             |
| Whitelist          | IP addresses never blocked, one per line.                           |

## Files

```
modules/ipblockprotection/
├── ipblockprotection.php        Main module class (hook + admin form)
├── classes/
│   ├── IpBlockClient.php        HTTP POST client (1s timeout)
│   └── IpBlockChecker.php       Whitelist + cache + fail mode + real IP
└── README.md
```

## Notes

* The API key is stored in the `ps_configuration` table. PrestaShop does not
  provide native at-rest field encryption for module configuration; restrict
  DB/back-office access accordingly.
* Add a `logo.png` (32x32) in the module root for a Module Manager icon (optional).
