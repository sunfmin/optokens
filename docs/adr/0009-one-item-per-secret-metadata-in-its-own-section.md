# One vault item per Secret, its metadata in a section of its own

Decided by the tech lead for Felix, when this storage was planned: 「Chose: a section of its own, because a user Field may be called `kind` or `description` (a Profile's env var); keeping metadata in its own section means a label never collides with it.」

One Secret is one item of the vault, of the category `SECURE_NOTE`, titled as decision record 13 says (it was `<service>/<account>`) and tagged `optokens`. Each Field is a field of the section `fields`, labelled with the Field's label; a single value is that section's one field, `value`. The kind (`static` or `profile`), the description (since decision record 14, the item's notes), and the shape (`value` or `fields`) are fields of the section `optokens`.

The Meta is a field `meta` of the section `optokens` too: one JSON object written compact, absent when the Secret has none (an item written before Meta has none). Meta is a field of its own, not folded into the description: it is data a program reads, not prose (Felix, 2026-11-27).

Reading an item back gives exactly the Secret that was stored. An item without the `optokens` tag, or whose `optokens` section is not this shape, is refused by name, never guessed at. `put` reads the item, merges, and writes it whole with `op item create` or `op item edit`, the template on `op`'s stdin. An edit template replaces the whole item, so it carries what optokens does not own: every other tag, section and field (mytokens' tags and sections; the notes, until decision record 14 made them the Description), read past and never refused, as mytokens writes and reads this layout too (Felix, 2026-11-27: 「双向同步要」).

## Considered Options

- Metadata in the item's notes.
- Metadata in tags.
- Metadata in a section of its own: chosen, because a user's Field may be called `kind` or `description` (a Profile's environment variable); in its own section a label never collides with it.

Undo: a reader of the old layout, and a migration in `put`.
