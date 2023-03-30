# Linux 4.19 kernel for Redmi K40 (alioth/in)

## Source code mirrors
Because of CGF (China's Great Firewall),
the latest code of this kernel has been moved to **Codeberg** now.
But all of mirrors will auto sync from the repo at Codeberg.

Please visit Codeberg page for getting the latest download and changes.

- **[Codeberg](https://gitea.com/LeviMarvin/kernel_xiaomi_alioth)**
- [Github](https://github.com/LeviMarvin/kernel_xiaomi_alioth)
- [Gitlab](https://gitlab.com/lmperf/kernel/alioth)

## Feature
- Linux Upstream: `4.19.y`/`4.19.278`
- ACK code branch: `android-4.19-stable`/`4.19.278`
    - Extra: `android-trusty-4.19`
- CLO code tag: `LA.UM.9.12.r1-15200.02-SMxx50.0`
- KernelSU version: **10704**
- CPU Freq: Ondemand
- Xiaomi drivers.
- KVM support enabled.

## Problem
- None for now.

## Install
### In Recovery
**Beforce start, TWRP and the Recovery based on it are recommended.**

Do not flash dtbo.img file if you are using MIUI.

1. Goto [Releases](https://codeberg.org/LeviMarvin/kernel_xiaomi_alioth/releases) page
and download `lmperf.zip` file from the latest release.
2. Push `lmperf.zip` file to your phone. (Skip if your have download it on your phone).
3. Reboot into Recovery mode, flash (aka install) the zip file, and reboot your phone.
4. Enjoy it.

### Flash boot.img
1. Goto [Releases](https://codeberg.org/LeviMarvin/kernel_xiaomi_alioth/releases) page
and download `Image` file from the latest release.
2. Unpack the `boot.img` which file you want to replace the kernel with lmperf kernel.
3. Copy and replace `Image`/`kernel` file (with same name) to unpacked `boot.img` directory.
4. Repack the `boot.img` file with replaced kernel file.
5. Reboot into Bootloader mode, flash boot.img to the boot partition of your phone.
