#!/bin/bash

export ARCH=arm64
export KERNEL_ROOTDIR=`pwd`
export KERNEL_OUTDIR=${KERNEL_ROOTDIR}/out
target=alioth_lmperf_defconfig

function clean() {
cd ${KERNEL_ROOTDIR}
make mrproper
git restore drivers/*
}

make ${target} LLVM=1 LLVM_IAS=1 O=${KERNEL_OUTDIR} ARCH=${ARCH} SUBARCH=arm64 CC=clang LD=ld.lld
make menuconfig LLVM=1 LLVM_IAS=1 O=${KERNEL_OUTDIR} ARCH=${ARCH} SUBARCH=arm64 CC=clang LD=ld.lld
make savedefconfig LLVM=1 LLVM_IAS=1 O=${KERNEL_OUTDIR} ARCH=${ARCH} SUBARCH=arm64 CC=clang LD=ld.lld
mv ${KERNEL_OUTDIR}/defconfig arch/${ARCH}/configs/${target}
clean
