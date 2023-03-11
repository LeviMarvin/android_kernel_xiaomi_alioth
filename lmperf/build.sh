#!/bin/bash

export ARCH=arm64
export DTC_EXT=/usr/bin/dtc
#export KBUILD_BUILD_USER=levimarvin
#export KBUILD_BUILD_HOST=lmsite.eu.org
export KERNEL_ROOTDIR=`pwd`
export KERNEL_OUTDIR=${KERNEL_ROOTDIR}/out
target=alioth_lmperf_defconfig

echo "Start building..."
cd ${KERNEL_ROOTDIR}
make LLVM=1 LLVM_IAS=1 ARCH=${ARCH} O=${KERNEL_OUTDIR} ARCH=${ARCH} SUBARCH=arm64 CC=clang LD=ld.lld ${target}
cd ${KERNEL_OUTDIR}
make -j$(nproc) LLVM=1 LLVM_IAS=1 O=${KERNEL_OUTDIR} ARCH=${ARCH} SUBARCH=arm64 CC=clang LD=ld.lld CLANG_TRIPLE=aarch64-linux-gnu- CROSS_COMPILE=aarch64-linux-gnu- CROSS_COMPILE_ARM32=arm-linux-gnueabi-

echo "Packaging..."
cd ${KERNEL_ROOTDIR}
./lmperf/package.sh
