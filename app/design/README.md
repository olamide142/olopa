# Olopa design system

One palette, two surfaces.

- **`tokens.css`** is the single source of truth for colour, radius and the mono stack.
- `app/control_plane/web` (the fleet console) and `app/command` (the desktop workstation)
  both `@import` it from their own `index.css`. Neither app defines colour values of its
  own; they add only app-specific chrome — scrollbars, window behaviour, animations.

## Theme

**Light is the default.** An unset preference resolves to light rather than following the
OS, so both surfaces open the same way on a fresh machine. Dark is opt-in through the
`dark` class on `<html>`, toggled from each app's `useTheme` hook and remembered in
`localStorage`:

| Surface | Storage key | Toggle location |
| --- | --- | --- |
| Console | `olopa_theme` | topbar, right of the identity chip |
| Desktop | `olopa_command_theme` | sidebar footer, next to the palette button |

The two hooks are deliberate duplicates (~30 lines each) rather than a shared import: each
app typechecks only its own `src` tree, and a cross-root import would need both tsconfig
`include` and Vite `fs.allow` changes for no real gain. Keep them in sync.

## Naming

The canonical vocabulary is shadcn-style: `background`, `foreground`, `card`, `muted`,
`muted-foreground`, `border`, `primary`, `accent`, `popover`, `sidebar`, plus Olopa's
additions — `surface-2`, `faint`, `border-strong`, and the semantics `success`, `warning`,
`danger`, `info`, `violet`.

Two rules worth stating because they were the actual source of drift:

1. **`primary` is the brand blue. `accent` is a subtle interactive surface, not a colour.**
   The desktop app originally used `accent` to mean "brand amber", which collided with the
   console's shadcn meaning. Brand is always `primary`.
2. The brand blue is `#2f78e6` light / `#58a0ff` dark, taken from the shipped control-plane
   templates, which predate both apps.

`tokens.css` also exports short aliases the desktop's dense styling uses — `bg`, `fg`,
`fg-muted`, `fg-faint`, `surface`, `rail`, `ok`, `warn`. These are the *same variables*, so
`bg-surface` and `bg-card` are identical by construction. New code should prefer the
canonical names.

## Changing a colour

Edit `tokens.css`, then rebuild both:

```bash
make web-build desktop-build
```
