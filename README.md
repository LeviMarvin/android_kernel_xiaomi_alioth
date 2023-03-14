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
- Linux Upstream: `4.19.y`/`4.19.277`
- ACK code branch: `android-4.19-stable`/`4.19.277`
    - Extra: `android-trusty-4.19`
- CLO code tag: `LA.UM.9.12.r1-15200-SMxx50.QSSI13.0`
- KernelSU version: **10679** (Updated at 20230313)
- Xiaomi driver:
    - Millet
    - `RTMM`
    - `FRAGMENTION`
    - `CAM_RECLAIM`
    - `RPI`
- CPU Freq: Ondemand
- Supported: `devfreq`, `kprofile`

## Problem
- Not for now

## Report an Issue
**If you want to report an issue to me, please create issues on Codeberg page!**
You need to provide these informations:
1. The basic informations about your phone:
    - ROM type (like `MIUI`, `AOSP`, etc.)
    - ROM name (like `MIUI 14`, `ArrowOS`, `dotOS`, etc.)
    - Android version (like `11(R)`,`12(S)`,`13(T)`, etc.)
    - Kernel version
        1. Version of the kernel from ROM.
        2. Install version of the kernel.
2. Issue informations:
    - Type (Choose from: `Auto Reboot`, `Function Lost`, `Other`)
    - Steps to review
    - Kernel log (If you can provide. Like `/proc/kmsg`, `/data/vendor/diag/last_kmsg`, etc.)
Thank you for your report, let's make the kernel to be better!

## Install
### In Kernel Flasher App
1. Goto [Releases](https://codeberg.org/LeviMarvin/kernel_xiaomi_alioth/releases) page
and download `lmperf.zip` file from the latest release.
2. Push `lmperf.zip` file to your phone. (Skip if your have download it on your phone).
3. Open Kernel Flasher Application and click the "View" on your slot.
4. Click "Flash" button and choose `lmperf.zip` file.
4. Reboot and enjoy it.

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
2. Unpack the `boot.img` file which you want to replace the kernel.
3. Copy and replace `Image` file to unpacked `boot.img` directory.
4. Repack the `boot.img` file with this kernel `Image` file.
5. Reboot into Bootloader mode, flash boot.img to the boot partition of your phone.
