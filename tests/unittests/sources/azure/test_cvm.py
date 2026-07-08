# This file is part of cloud-init. See LICENSE file for license information.

from unittest import mock

import pytest

from cloudinit import subp
from cloudinit.sources.azure import cvm

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
        mock_subp.assert_called_once_with(
            [cvm.SECRETS_TOOL, "is-cvm"]
        )

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
