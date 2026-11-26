# A Secret's Description is the item's notes

Replaces the Description's place in decision record 9. Decided by the control tech lead for Felix: 「Chose: notes only, because the notes are what 1Password shows in its list, and the section was chosen for metadata only to avoid clashing with a Field label, which the notes cannot do.」

1Password's item list shows the start of an item's notes under its title (`op item list` gives it as `additional_information`). With the Description in the section `optokens`, and the notes empty, the list showed titles only; Felix asked for the Description there (2026-11-27).

A Secret's Description is the item's notes: the field of `purpose` `NOTES`, id and label `notesPlain`. `put` writes it whole; a Secret without a Description has empty notes, and `put --description ""` clears it. Reading takes the whole notes, empty as none. The notes are optokens' own now, no longer kept as another program's: a person who writes notes in 1Password writes the Description.

An item in the earlier layout, its Description a field `description` of the section `optokens`, is still read: the Description is that field's when it is there and not empty (it is what optokens or mytokens last wrote), else the notes'. Such an item is not current, so the next `put` rewrites it: the field gone, the Description in the notes. Notes it overwrites stay in 1Password's item history.

## Considered Options

- Notes only: chosen. The notes cannot clash with a Field's label, the reason decision record 9 kept metadata in a section.
- The section only, as before. Rejected: 1Password's list does not show it.
- Both. Rejected: one fact, one home (mytokens decision record 24).

Undo: a layout reading the section again; the notes stay as they are.
