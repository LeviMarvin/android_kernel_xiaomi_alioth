#!/bin/bash

export KERNEL_ROOTDIR=`pwd`
export KERNEL_OUTDIR=${KERNEL_ROOTDIR}/out
export ANYKERNEL3_ROOTDIR=${KERNEL_ROOTDIR}/lmperf/AnyKernel3
PRODUCT_OUTDIR=${KERNEL_ROOTDIR}/lmperf/out

echo "Clean the output dir..."
rm -rf ${PRODUCT_OUTDIR}/*

echo "Copy files..."
cp ${KERNEL_OUTDIR}/arch/arm64/boot/Image ${ANYKERNEL3_ROOTDIR}/
cp ${KERNEL_OUTDIR}/arch/arm64/boot/Image ${PRODUCT_OUTDIR}/
cp ${KERNEL_OUTDIR}/arch/arm64/boot/dtbo.img ${PRODUCT_OUTDIR}/

echo "Set permissions..."
cd ${ANYKERNEL3_ROOTDIR}/
chmod +x Image

echo "Compress..."
zip -r lmperf.zip anykernel.sh Image META-INF modules patch ramdisk tools
cp lmperf.zip ${PRODUCT_OUTDIR}/

echo "Clean the AnyKernel3 work dir..."
rm -rf ${ANYKERNEL3_ROOTDIR}/Image ${ANYKERNEL3_ROOTDIR}/lmperf.zip

echo "Package done!"
echo "You can copy the file at \"${KERNEL_ROOTDIR}/lmperf/out/\""
