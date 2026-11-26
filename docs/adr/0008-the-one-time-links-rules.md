# The one-time link: a fresh token, one submission, ten minutes, the tailnet only

Felix, 2026-11-26, in the control session:

```text
「照 mytokens ADR-0010 的规则：… 链接带一个新生成的 128 位随机 token，只能提交一次，10 分钟过期 … 只监听 tailnet 地址（`tailscale ip`），不监听别的网卡。能拿到 `tailscale cert` 就用 HTTPS，拿不到就用 tailnet 上的 HTTP，并打印原因。没有 tailscale 就什么都不存，说清楚缺什么。」
```

The rules are mytokens' (its decision record 10 and its `OneTimeLink.swift`, at commit 13ba0f1 of github.com/sunfmin/mytokens), as pure code with no sockets: what serves a link hands it each request and the time.

A link's token is 128 bits from the OS's CSPRNG, written as 32 lowercase hex digits, and is the whole of its path; a request's path is compared with it in constant time.

The first complete POST with the right token before expiry gives back the values, and no request after it does: each answers 410, "This link was already used."

A link expires 10 minutes after it is made, one constant that the code and the page say; from then on each request answers 410, "This link expired. Nothing was stored." The help of `put` and `init` says it from that constant too.

A wrong path answers 404 and a method other than GET or POST 405; a POST with an empty field answers the form again, 400, with "Every field needs a value."

The page names the Secret (`<service>/<account>`) and its Description, and has one input per Field it asks for: plain text for a `--show` Field, a password input for the rest; a Field already set shows only "already set", its value never on the page, and every piece of text on it is HTML-escaped.

The link listens only on the tailnet address `tailscale ip` names that is on one of this host's interfaces; with no `tailscale` or no such address it stores nothing, and its refusal names what is missing.

With a certificate from `tailscale cert` the link is HTTPS; when `tailscale cert` fails it is plain HTTP on the tailnet, and the reason printed with it gives the error and the fix: an admin runs `sudo tailscale set --operator=<user>`, and HTTPS Certificates are on for the tailnet.

## Considered Options

- Listen on every interface and check the client's address. Rejected: the owner's rule is to listen on no other interface.
- Refuse to serve without a certificate. Rejected: the owner chose plain HTTP on the tailnet, which WireGuard encrypts, with its reason printed.
- mytokens' rules, ported: chosen.

Undo: the module `src/link`, and this ADR's promises in `truefit.toml`.
