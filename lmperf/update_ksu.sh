#!/bin/bash
export KERNEL_ROOTDIR=`pwd`
export KERNEL_OUTDIR=${KERNEL_ROOTDIR}/out

echo "Update kernel..."
cd ${KERNEL_ROOTDIR}
git pull
echo "Update KernelSU..."
cd ${KERNEL_ROOTDIR}/KernelSU/
git pull
cp -r ${KERNEL_ROOTDIR}/KernelSU/kernel/* ${KERNEL_ROOTDIR}/drivers/kernelsu/

git commit -m "ksu: Update to latest version."
git push

