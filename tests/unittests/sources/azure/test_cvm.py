# This file is part of cloud-init. See LICENSE file for license information.

from unittest import mock

import pytest

from cloudinit import subp
from cloudinit.sources.azure import cvm, errors

# CPUID register tuples (eax, ebx, ecx, edx) keyed by leaf, used to drive
# the mocked _cpuid() in the native-detection tests.
_HV_VENDOR_REGS = (cvm._HV_ISOLATION_LEAF,) + cvm._HV_VENDOR
_NON_HV_VENDOR_REGS = (cvm._HV_ISOLATION_LEAF, 0x0, 0x0, 0x0)


def _isolation_regs(isolation_type: int):
    """CPUID registers for the isolation leaf with EBX[0:4] == isolation."""
    return (0x0, isolation_type, 0x0, 0x0)


@pytest.fixture
def mock_subp():
    with mock.patch.object(cvm, "subp") as m:
        m.ProcessExecutionError = subp.ProcessExecutionError
        yield m.subp


@pytest.fixture
def mock_cpuid():
    with mock.patch.object(cvm, "_cpuid", autospec=True) as m:
        yield m


@pytest.fixture
def mock_os_path_exists():
    with mock.patch.object(cvm.os.path, "exists", return_value=True) as m:
        yield m


class TestIsCvmNative:
    def test_snp_is_cvm(self, mock_cpuid, mock_os_path_exists):
        mock_cpuid.side_effect = [
            _HV_VENDOR_REGS,
            _isolation_regs(cvm._SNP),
        ]

        assert cvm._is_cvm_native() is True

    def test_tdx_is_cvm(self, mock_cpuid, mock_os_path_exists):
        mock_cpuid.side_effect = [
            _HV_VENDOR_REGS,
            _isolation_regs(cvm._TDX),
        ]

        assert cvm._is_cvm_native() is True

    def test_vbs_is_not_cvm(self, mock_cpuid, mock_os_path_exists):
        mock_cpuid.side_effect = [
            _HV_VENDOR_REGS,
            _isolation_regs(0x1),
        ]

        assert cvm._is_cvm_native() is False

    def test_non_hyperv_vendor_is_not_cvm(
        self, mock_cpuid, mock_os_path_exists
    ):
        mock_cpuid.side_effect = [_NON_HV_VENDOR_REGS]

        assert cvm._is_cvm_native() is False

    def test_missing_isolation_leaf_is_not_cvm(
        self, mock_cpuid, mock_os_path_exists
    ):
        # eax (max leaf) lower than the isolation leaf we need.
        mock_cpuid.side_effect = [
            (cvm._HV_VENDOR_LEAF,) + cvm._HV_VENDOR,
        ]

        assert cvm._is_cvm_native() is False

    def test_unreadable_device_raises(self, mock_cpuid, mock_os_path_exists):
        mock_cpuid.side_effect = OSError("boom")

        with pytest.raises(cvm.CvmDetectionError):
            cvm._is_cvm_native()

    def test_missing_device_loads_module(
        self, mock_subp, mock_cpuid, mock_os_path_exists
    ):
        mock_os_path_exists.return_value = False
        mock_cpuid.side_effect = [
            _HV_VENDOR_REGS,
            _isolation_regs(cvm._SNP),
        ]

        assert cvm._is_cvm_native() is True
        mock_subp.assert_called_once_with(["modprobe", "cpuid"])

    def test_present_device_does_not_load_module(
        self, mock_subp, mock_cpuid, mock_os_path_exists
    ):
        mock_os_path_exists.return_value = True
        mock_cpuid.side_effect = [
            _HV_VENDOR_REGS,
            _isolation_regs(cvm._SNP),
        ]

        assert cvm._is_cvm_native() is True
        mock_subp.assert_not_called()

    def test_modprobe_failure_is_ignored(
        self, mock_subp, mock_cpuid, mock_os_path_exists
    ):
        mock_os_path_exists.return_value = False
        mock_subp.side_effect = subp.ProcessExecutionError(
            cmd=["modprobe", "cpuid"], exit_code=1
        )
        mock_cpuid.side_effect = [
            _HV_VENDOR_REGS,
            _isolation_regs(cvm._SNP),
        ]

        assert cvm._is_cvm_native() is True


class TestIsCvmTool:
    def test_exit_zero_is_cvm(self, mock_subp):
        mock_subp.return_value = subp.SubpResult("", "")

        assert cvm._is_cvm_tool() is True
        mock_subp.assert_called_once_with([cvm.SECRETS_TOOL, "is-cvm"])

    def test_exit_one_is_not_cvm(self, mock_subp):
        mock_subp.side_effect = subp.ProcessExecutionError(
            cmd=[cvm.SECRETS_TOOL, "is-cvm"], exit_code=1
        )

        assert cvm._is_cvm_tool() is False

    def test_unexpected_exit_raises(self, mock_subp):
        mock_subp.side_effect = subp.ProcessExecutionError(
            cmd=[cvm.SECRETS_TOOL, "is-cvm"], exit_code=2
        )

        with pytest.raises(cvm.CvmDetectionError):
            cvm._is_cvm_tool()

    def test_tool_absent_raises(self, mock_subp):
        mock_subp.side_effect = subp.ProcessExecutionError(
            cmd=[cvm.SECRETS_TOOL, "is-cvm"],
            reason=FileNotFoundError("not found"),
            errno=2,
        )

        with pytest.raises(cvm.CvmDetectionError):
            cvm._is_cvm_tool()


class TestIsCvm:
    def test_native_true_skips_tool(self, monkeypatch):
        tool = mock.Mock()
        monkeypatch.setattr(cvm, "_is_cvm_native", lambda: True)
        monkeypatch.setattr(cvm, "_is_cvm_tool", tool)

        assert cvm.is_cvm() is True
        tool.assert_not_called()

    def test_native_false_skips_tool(self, monkeypatch):
        tool = mock.Mock()
        monkeypatch.setattr(cvm, "_is_cvm_native", lambda: False)
        monkeypatch.setattr(cvm, "_is_cvm_tool", tool)

        assert cvm.is_cvm() is False
        tool.assert_not_called()

    def test_native_undetermined_falls_back_to_tool_true(self, monkeypatch):
        def raise_native():
            raise cvm.CvmDetectionError("undetermined")

        monkeypatch.setattr(cvm, "_is_cvm_native", raise_native)
        monkeypatch.setattr(cvm, "_is_cvm_tool", lambda: True)

        assert cvm.is_cvm() is True

    def test_native_undetermined_falls_back_to_tool_false(self, monkeypatch):
        def raise_native():
            raise cvm.CvmDetectionError("undetermined")

        monkeypatch.setattr(cvm, "_is_cvm_native", raise_native)
        monkeypatch.setattr(cvm, "_is_cvm_tool", lambda: False)

        assert cvm.is_cvm() is False

    def test_both_undetermined_raises(self, monkeypatch):
        def raise_native():
            raise cvm.CvmDetectionError("native undetermined")

        def raise_tool():
            raise cvm.CvmDetectionError("tool undetermined")

        monkeypatch.setattr(cvm, "_is_cvm_native", raise_native)
        monkeypatch.setattr(cvm, "_is_cvm_tool", raise_tool)

        with pytest.raises(cvm.CvmDetectionError):
            cvm.is_cvm()


class TestIsToolPresent:
    def test_present(self):
        with mock.patch.object(
            cvm.subp, "which", return_value="/usr/bin/" + cvm.SECRETS_TOOL
        ) as m_which:
            assert cvm.is_tool_present() is True

        m_which.assert_called_once_with(cvm.SECRETS_TOOL)

    def test_absent(self):
        with mock.patch.object(cvm.subp, "which", return_value=None):
            assert cvm.is_tool_present() is False


class TestIsSecretsProvisioningEnabled:
    def test_exit_zero_is_enabled(self, mock_subp):
        mock_subp.return_value = subp.SubpResult("", "")

        assert cvm.is_secrets_provisioning_enabled() is True
        mock_subp.assert_called_once_with(
            [cvm.SECRETS_TOOL, "is-secrets-provisioning-enabled"]
        )

    def test_exit_one_is_disabled(self, mock_subp):
        mock_subp.side_effect = subp.ProcessExecutionError(
            cmd=[cvm.SECRETS_TOOL, "is-secrets-provisioning-enabled"],
            exit_code=1,
        )

        assert cvm.is_secrets_provisioning_enabled() is False

    def test_unexpected_exit_raises(self, mock_subp):
        mock_subp.side_effect = subp.ProcessExecutionError(
            cmd=[cvm.SECRETS_TOOL, "is-secrets-provisioning-enabled"],
            exit_code=2,
            stderr="boom",
        )

        with pytest.raises(errors.ReportableErrorSecretsTool) as exc_info:
            cvm.is_secrets_provisioning_enabled()

        error = exc_info.value
        assert error.supporting_data["command"] == (
            "is-secrets-provisioning-enabled"
        )
        assert error.supporting_data["exit_code"] == 2
        assert error.supporting_data["stderr"] == "boom"
        # stdout must never be surfaced (it may be a plaintext secret).
        assert "stdout" not in error.supporting_data


class TestUnprotectSecret:
    def test_success_returns_stdout(self, mock_subp):
        mock_subp.return_value = subp.SubpResult("plaintext-secret", "")

        assert (
            cvm.unprotect_secret("customData", "encrypted-token")
            == "plaintext-secret"
        )
        mock_subp.assert_called_once_with(
            [cvm.SECRETS_TOOL, "unprotect-secret", "--policy", "0"],
            data="encrypted-token",
        )

    def test_failure_logs_and_returns_original_token(self, mock_subp, caplog):
        mock_subp.side_effect = subp.ProcessExecutionError(
            cmd=[cvm.SECRETS_TOOL, "unprotect-secret", "--policy", "0"],
            exit_code=1,
            stdout="leaked-secret",
            stderr="bad token",
        )

        with caplog.at_level("ERROR"):
            result = cvm.unprotect_secret("adminPassword", "encrypted-token")

        assert result == "encrypted-token"
        assert "unprotect-secret failed for field=adminPassword" in caplog.text
