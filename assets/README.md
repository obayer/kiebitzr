# Assets

| File | What it is | Where it is used |
|---|---|---|
| `banner.svg` | 1280×400, the full lockup on a rounded dark tile | the strip at the top of `README.md` |
| `social-preview.svg` | 1280×640, the same lockup, full-bleed | source for `social-preview.png` |
| `social-preview.png` | 1280×640, 209 kB, indexed | uploaded as GitHub's social preview |
| `kiebitzr.svg` | the lapwing on a rounded dark tile | nothing in this repository |
| `kibi.svg` | the lapwing alone, transparent background | nothing in this repository |
| `favicon.svg` | 128×128, the `k` mark on a rounded dark tile | nothing in this repository |

The last three are referenced nowhere in the tree. They are kept because they are the marks
the other files are built from, not because something renders them.

## Three files carry the same artwork

The lockup — bird, wordmark, dot, claim — is **byte-identical in `banner.svg` and
`social-preview.svg`**, 28,279 bytes, 97 % of each file, and `social-preview.png` is a third,
rasterised copy. It is duplicated rather than referenced because both SVGs have to stand alone:
GitHub serves README images through a sanitising proxy that strips external references, so
neither `<use href="other.svg#id">` nor a `#view` fragment survives rendering.

So a change to the artwork is a change to **all three**: edit both SVGs, then export the PNG
again. Nothing checks this — the duplicate is 28 kB of outlined path data that no diff review
will catch. `social-preview.svg` places the lockup with `translate(19.6 118) scale(1.08)`; the
rings, the ground line and the gradient centre move with it.

The text carries no `font-family`: every glyph is an outlined path. That makes rasterising
reproducible, and it means new wording cannot be typed in — it has to be set in the original
font and converted to outlines.

## Exporting the PNG

GitHub's social preview takes PNG, JPG or GIF under 1 MB and renders it at 1280×640. Upload it
under Settings → General → Social preview.

**Do not export with ImageMagick.** Its built-in MSVG renderer drops the `radialGradient` and
flattens the background to black — which hits `banner.svg` and `kiebitzr.svg` just as hard,
since both are built on the same gradient. Measured on a half-gradient, half-flat test file:

```
gradient half: srgb(0,0,0)
flat half:     srgb(29,74,64)   # = #1d4a40, correct
```

`rsvg-convert -w 1280 -h 640 social-preview.svg -o social-preview.png` renders it correctly, as
does `resvg`.
