# psvitapupextractor

A **PS Vita firmware update (PUP) unpacker** for Windows, with a GUI — a native C# port of
Team Molecule's [sceutils](https://github.com/TeamMolecule/sceutils) `pup_fiction.py`.

It runs the full pipeline: split the `SCEUF` container, decrypt every SCE package,
`self2elf` the loaders, unpack and decrypt `SLB2`, join and extract the `os0`/`vs0`
filesystems, and recursively decrypt every system module (`.self`/`.skprx`/`.suprx`) to
ELF.

## Key fallback

The headline feature: for every SCE file it tries the three key sets **in order** and uses
whichever one actually decrypts it (verified by the metadata padding check):

```
proto (External GEN2)  ->  internal (Internal GENX)  ->  external (External GEN3)
```

All three keystores are embedded, so a single build handles proto, internal and retail
packages without you choosing a keyset.

## Features

- Container split, package decrypt, `self2elf`, `SLB2` decrypt (incl. `nsbl.bin` via
  `unarzl`), `os0`/`vs0` filesystem extraction, recursive module decryption.
- **Batch mode**: Input-folder + Output-folder fields — processes every `*.pup` in the
  input folder into its own `<name>_ex` output folder.
- Optional **`vs0`/`vd0`** extraction (checkbox — it's large) and optional **SLB2** step.
- Firmware-aware `second_loader`/`secure_kernel` `.enc` key (3.70+ differs from earlier).
- Runs on the **.NET Framework 4.x** that ships with Windows.

## External helpers

Mirroring `pup_fiction`, two small helpers are used when present:

- **7-Zip** (`C:\Program Files\7-Zip\7z.exe`, auto-detected) to extract the FAT `os0`/`vs0`
  images. If absent, `os0.bin`/`vs0.bin` are left raw.
- **`unarzl.exe`** (included, prebuilt from the sceutils ARZL decompressor) for the single
  `nsbl.bin` step. **It must sit next to `psvitapupextractor_gui.exe`.**

## Build

No .NET SDK required:

```
build.cmd
```

(calls `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe`). GitHub Actions builds a
Windows release on every `v*` tag (see `.github/workflows/release.yml`); the release zip
contains both `psvitapupextractor_gui.exe` and `unarzl.exe`. `unarzl.c`/`Makefile` are
included to rebuild the helper yourself.

## Credits & license

Format logic, pipeline and key sets are ported from **Team Molecule — sceutils**
(`scetypes.py`, `sceutils.py`, `self2elf.py`, `scedecrypt.py`, `pup_fiction.py`,
`unarzl/`), MIT-licensed. This project keeps the **MIT license** — see [LICENSE](LICENSE).

Reverse-engineering / homebrew tooling for firmware you own; all keys used are already
public. No warranty.
