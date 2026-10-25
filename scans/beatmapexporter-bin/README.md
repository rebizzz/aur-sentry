# beatmapexporter-bin
### [The Source Repo](https://github.com/kabiiQ/BeatmapExporter/) | [AUR Page](https://aur.archlinux.org/packages/beatmapexporter-bin)
You can contribute to package with creating [an issue](https://github.com/Parsa-GP/beatmapexporter-bin/issues) in github or adding a comment in [AUR Page](https://aur.archlinux.org/packages/beatmapexporter-bin).
## Hash error
If there's a sha256 error, you can fix it by skipping the hash check.
1. First, clone the repo:
``` sh
# Clone from Arch repo
git clone https://aur.archlinux.org/beatmapexporter-bin.git

# Clone from Github
git clone https://github.com/Parsa-GP/beatmapexporter-bin.git
```
2. Edit the PKGBUILD to not check for version of those files:
``` PKGBUILD
sha256sums=("SKIP" "SKIP")
```
3. Install the modified package:
``` sh
makepkg -si
```
