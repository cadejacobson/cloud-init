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
from cloudinit.sources.azure import errors

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


def is_tool_present() -> bool:
    """True when azure-protected-secrets-tool is available on PATH."""
    return subp.which(SECRETS_TOOL) is not None


def _run_tool(command: str) -> bool:
    """Run an azure-protected-secrets-tool subcommand with a 0/1 contract.

    :return: True on exit 0, False on exit 1 (the documented "false" result).
    :raises errors.ReportableErrorSecretsTool: on any other (unexpected) exit
        code, with the reason taken from stderr. stdout is never surfaced --
        for some commands (e.g. unprotect-secret) it is the plaintext secret.
    """
    try:
        subp.subp([SECRETS_TOOL, command])
    except subp.ProcessExecutionError as error:
        # exit 1 is the documented "false" result, not an error.
        if error.exit_code == 1:
            return False
        raise errors.ReportableErrorSecretsTool(
            command=command, exception=error
        ) from error
    return True


def is_secrets_provisioning_enabled() -> bool:
    """True when secrets provisioning is enabled for this VM (v1).

    Runs ``azure-protected-secrets-tool is-secrets-provisioning-enabled``:
    exit 0 means enabled, exit 1 means disabled.

    :raises errors.ReportableErrorSecretsTool: on any other (unexpected) exit
        code, so the caller reports it (reason from stderr) rather than
        silently continuing.
    """
    return _run_tool("is-secrets-provisioning-enabled")


def unprotect_secret(field: str, token: str) -> str:
    """Decrypt a single ovf-env.xml secret via azure-protected-secrets-tool.

    Runs ``unprotect-secret --policy 3`` (require both signature and
    encryption) with the encrypted ``token`` piped on stdin and returns the
    decrypted plaintext, which the tool writes to stdout.

    The return value -- and the subprocess output -- is the plaintext secret
    and must never be logged.

    :param field: the ovf-env.xml field name, used only for error reporting.
    :param token: the encrypted JWT read from ovf-env.xml.
    On failure, logs an error and returns the original token so provisioning
    can continue in best-effort mode.
    """
    # DEBUG: DO NOT MERGE -- logs the incoming token (to confirm the field
    # arrived encrypted) and the decrypted plaintext (to confirm the tool
    # ran). This intentionally leaks the secret. Remove before production.
    LOG.warning("unprotect-secret: field=%s incoming token=%r", field, token)
    try:
        result = subp.subp(
            [SECRETS_TOOL, "unprotect-secret", "--policy", "3"],
            data=token,
        )
    except subp.ProcessExecutionError as error:
        # raise errors.ReportableErrorSecretDecryptionFailure(
        #     field=field, exception=error
        # ) from error
        LOG.error(
            "unprotect-secret failed for field=%s; continuing with "
            "original value: %s",
            field,
            error,
        )
        return token
    # DEBUG: DO NOT MERGE -- see note above. Leaks decrypted plaintext.
    LOG.warning(
        "unprotect-secret: field=%s decrypted plaintext=%r",
        field,
        result.stdout,
    )
    return result.stdout
