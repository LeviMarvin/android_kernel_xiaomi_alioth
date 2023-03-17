#!/bin/bash

export ARCH=arm64
export SUBARCH=arm64
export DTC_EXT=/usr/bin/dtc
export KBUILD_BUILD_USER=lmperf
export KBUILD_BUILD_HOST=localhost
export KERNEL_ROOTDIR=`pwd`
export KERNEL_OUTDIR=${KERNEL_ROOTDIR}/out
target=alioth_lmperf_defconfig

echo "Start building..."
cd ${KERNEL_ROOTDIR}
make LLVM=1 LLVM_IAS=1 O=${KERNEL_OUTDIR} ARCH=${ARCH} SUBARCH=${SUBARCH} CC=clang LD=ld.lld ${target}
cd ${KERNEL_OUTDIR}
make -j$(nproc) LLVM=1 LLVM_IAS=1 O=${KERNEL_OUTDIR} ARCH=${ARCH} SUBARCH=${SUBARCH} CC=clang LD=ld.lld CLANG_TRIPLE=aarch64-linux-gnu- CROSS_COMPILE=aarch64-linux-gnu- CROSS_COMPILE_ARM32=arm-linux-gnueabi- KBUILD_BUILD_USER=${KBUILD_BUILD_USER} KBUILD_BUILD_HOST=${KBUILD_BUILD_HOST}

if [ $? -eq 0 ]; then
echo "Packaging..."
cd ${KERNEL_ROOTDIR}
./lmperf/package.sh
else
echo "Build failed! Please check!"
fi
