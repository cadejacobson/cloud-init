# Copyright (C) 2026 Microsoft Corporation.
#
# This file is part of cloud-init. See LICENSE file for license information.
"""Confidential VM (CVM) isolation detection for the Azure datasource.

``is_cvm()`` reports whether cloud-init is running inside an Azure
Confidential VM (AMD SEV-SNP or Intel TDX). It prefers a native read of the
Hyper-V isolation type from ``/dev/cpu/0/cpuid`` and falls back to
``azure-protected-secrets-tool is-cvm`` only when the native read cannot
decide. Both key off the same Hyper-V CPUID leaves, so the two agree.

This module is not yet wired into the datasource; it only adds the detection
primitives.
"""

import logging
import os
import struct

from cloudinit import subp

LOG = logging.getLogger(__name__)

CPUID_DEVICE = "/dev/cpu/0/cpuid"
SECRETS_TOOL = "azure-protected-secrets-tool"

# Hyper-V CPUID leaves, matching azure-protected-secrets-tool.
_HV_VENDOR_LEAF = 0x40000000
_HV_ISOLATION_LEAF = 0x4000000C
_HV_VENDOR = (0x7263694D, 0x666F736F, 0x76482074)  # "Microsoft Hv"
_SNP, _TDX = 0x2, 0x3


class CvmDetectionError(Exception):
    """CVM isolation could not be determined."""


def _cpuid(leaf: int):
    """Return (eax, ebx, ecx, edx) for a CPUID leaf via /dev/cpu/0/cpuid."""
    fd = os.open(CPUID_DEVICE, os.O_RDONLY)
    try:
        return struct.unpack("<4I", os.pread(fd, 16, leaf))
    finally:
        os.close(fd)


def _is_cvm_native() -> bool:
    """Isolation type via /dev/cpu/0/cpuid (loads the cpuid module first).

    :raises CvmDetectionError: if the cpuid device cannot be read.
    """
    if not os.path.exists(CPUID_DEVICE):
        try:
            subp.subp(["modprobe", "cpuid"])
        except subp.ProcessExecutionError as error:
            LOG.debug("Failed to load cpuid module: %s", error)

    try:
        eax, ebx, ecx, edx = _cpuid(_HV_VENDOR_LEAF)
        if (ebx, ecx, edx) != _HV_VENDOR or eax < _HV_ISOLATION_LEAF:
            return False
        return (_cpuid(_HV_ISOLATION_LEAF)[1] & 0xF) in (
            _SNP,
            _TDX,
        )  # EBX[0:4]
    except OSError as error:
        raise CvmDetectionError(
            "cpuid device unreadable: %s" % error
        ) from error


def _is_cvm_tool() -> bool:
    """Fallback: azure-protected-secrets-tool is-cvm (exit 0 CVM, 1 not).

    :raises CvmDetectionError: when the answer is uncertain -- the tool is
        absent or exits with any code other than 0 or 1.
    """
    try:
        subp.subp([SECRETS_TOOL, "is-cvm"])
    except subp.ProcessExecutionError as error:
        # exit 1 (not a CVM) is expected, not an error.
        if error.exit_code == 1:
            return False
        raise CvmDetectionError(
            "%s is-cvm could not determine isolation: %s"
            % (SECRETS_TOOL, error)
        ) from error
    return True


def is_cvm() -> bool:
    """True inside an Azure Confidential VM (SNP or TDX); VBS is not.

    Prefer the native /dev/cpu/0/cpuid read; if it can't decide, fall back to
    the tool.

    :raises CvmDetectionError: when neither can decide (device unreadable and
        tool absent, or an unexpected tool exit) so the caller reports it
        rather than mistaking an undetermined CVM for a plain VM.
    """
    try:
        return _is_cvm_native()
    except CvmDetectionError as error:
        LOG.debug("Native CVM detection undetermined, trying tool: %s", error)

    return _is_cvm_tool()
