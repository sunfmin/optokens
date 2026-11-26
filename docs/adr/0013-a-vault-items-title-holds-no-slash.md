# A vault item's title holds no `/`; its name is in its section

Replaces the title of decision record 9. Decided by the control session for Felix: 「Chose: the mytokens form, because Felix said 「标题去掉斜杠可以」 (2026-11-27) and it is the only form `op://` can address.」

A Secret's item is titled `<service>`, or `<service>.<account>` when the account is not `default`: never a `/`, which `op read "op://<vault>/<title>/..."` cannot carry. It is the title mytokens gives its items, so both tools name one Secret the same way in a shared vault.

A service may hold a `.` (`name.com`), so the title alone does not say the name: the section `optokens` holds it, in the fields `service` and `account`, and reading takes the name from them, never by splitting the title. Two Secrets may share a title (`a.b/default` and `a/b`); optokens tells them apart by their sections, and `op://` cannot.

An item an earlier optokens wrote, titled `<service>/<account>` with no `service` or `account`, is still read by its title. The next `put` of that Secret rewrites it in this layout, the same item through `op item edit`, even when no value changes.

## Considered Options

- Keep `<service>/<account>`. Rejected: `op://` cannot reach it, so a person or script holding only `op` cannot read a Secret.
- `<service>` / `<service>.<account>`, the name in the section: chosen.

Undo: retitle back in `put`; reading the old title stays.
