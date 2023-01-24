#!/bin/bash
export ARCH=arm64
export DTC_EXT=/usr/bin/dtc
export KERNEL_ROOTDIR=`pwd`
export KERNEL_OUTDIR=${KERNEL_ROOTDIR}/out
target=alioth_lmperf_defconfig

cd ${KERNEL_ROOTDIR}
make ARCH=${ARCH} O=${KERNEL_OUTDIR} ${target}
cd ${KERNEL_OUTDIR}
make -j12 O=${KERNEL_OUTDIR} ARCH=${ARCH} SUBARCH=arm64 CC=clang CLANG_TRIPLE=aarch64-linux-gnu- CROSS_COMPILE=aarch64-linux-gnu- CROSS_COMPILE_ARM32=arm-linux-gnueabi-
