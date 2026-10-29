"""Temporary-root tests for the ownership-aware APT hook lifecycle."""

import json
from pathlib import Path

import pytest

from scanner.apt_lifecycle import (
    HOOK_NAME,
    STATE_NAME,
    LifecycleError,
    _atomic_write,
    disable_apt_hook,
    enable_apt_hook,
    install_apt_hook,
    integration_status,
    uninstall_apt_hook,
    validate_effective_hook_order,
    validate_trusted_runtime,
)


@pytest.fixture
def roots(tmp_path):
    apt = tmp_path / "etc/apt/apt.conf.d"
    state = tmp_path / "var/lib/linuxsecmonitor"
    apt.mkdir(parents=True)
    return apt, state


def test_install_enable_disable_uninstall_are_repeatable_and_preserve_other_config(roots):
    apt, state = roots
    unrelated = apt / "50proxy"
    unrelated.write_text("Acquire::http::Proxy \"http://proxy.invalid\";\n")
    assert integration_status(apt_conf_dir=apt, state_dir=state)["status"] == "not_installed"
    assert install_apt_hook(apt_conf_dir=apt, state_dir=state, python="/usr/bin/python3")["status"] == "enabled"
    assert install_apt_hook(apt_conf_dir=apt, state_dir=state, python="/usr/bin/python3")["status"] == "enabled"
    assert (apt / HOOK_NAME).stat().st_mode & 0o777 == 0o644
    assert (state / STATE_NAME).stat().st_mode & 0o777 == 0o600
    assert disable_apt_hook(apt_conf_dir=apt, state_dir=state)["status"] == "disabled"
    assert disable_apt_hook(apt_conf_dir=apt, state_dir=state)["status"] == "disabled"
    assert enable_apt_hook(apt_conf_dir=apt, state_dir=state)["status"] == "enabled"
    assert enable_apt_hook(apt_conf_dir=apt, state_dir=state)["status"] == "enabled"
    assert uninstall_apt_hook(apt_conf_dir=apt, state_dir=state)["status"] == "not_installed"
    assert uninstall_apt_hook(apt_conf_dir=apt, state_dir=state)["status"] == "not_installed"
    assert unrelated.read_text() == 'Acquire::http::Proxy "http://proxy.invalid";\n'
    assert not state.exists() or not list(state.iterdir())


def test_install_refuses_preexisting_hook_and_state_without_overwriting(roots):
    apt, state = roots
    hook = apt / HOOK_NAME
    hook.write_text("foreign config\n")
    with pytest.raises(LifecycleError, match="Refusing to overwrite"):
        install_apt_hook(apt_conf_dir=apt, state_dir=state, python="/usr/bin/python3")
    assert hook.read_text() == "foreign config\n"
    hook.unlink()
    state.mkdir(parents=True)
    receipt = state / STATE_NAME
    receipt.write_text('{"owner":"other"}')
    with pytest.raises(LifecycleError, match="already exists"):
        install_apt_hook(apt_conf_dir=apt, state_dir=state, python="/usr/bin/python3")
    assert receipt.read_text() == '{"owner":"other"}'


def test_disable_and_uninstall_refuse_modified_or_unowned_configuration(roots):
    apt, state = roots
    hook = apt / HOOK_NAME
    hook.write_text("foreign\n")
    with pytest.raises(LifecycleError, match="not recorded"):
        disable_apt_hook(apt_conf_dir=apt, state_dir=state)
    assert hook.read_text() == "foreign\n"
    hook.unlink()
    install_apt_hook(apt_conf_dir=apt, state_dir=state, python="/usr/bin/python3")
    hook.write_text(hook.read_text() + "// locally modified\n")
    with pytest.raises(LifecycleError, match="differs"):
        uninstall_apt_hook(apt_conf_dir=apt, state_dir=state)
    assert hook.exists() and (state / STATE_NAME).exists()


def test_install_rolls_back_partial_state_when_hook_write_fails(roots):
    apt, state = roots
    real_writer_calls = []

    def fail_hook(path: Path, data: bytes, mode: int):
        real_writer_calls.append(path)
        if path.name == HOOK_NAME:
            raise PermissionError("fixture failure")
        from scanner.apt_lifecycle import _atomic_write
        _atomic_write(path, data, mode)

    with pytest.raises(LifecycleError, match="rolled back"):
        install_apt_hook(apt_conf_dir=apt, state_dir=state, python="/usr/bin/python3", writer=fail_hook)
    assert real_writer_calls[-1].name == HOOK_NAME
    assert not (state / STATE_NAME).exists()
    assert not (apt / HOOK_NAME).exists()


def test_install_rolls_back_when_effective_hook_order_is_unsafe(roots):
    apt, state = roots

    def reject_order(python):
        raise LifecycleError("fixture has an earlier hook")

    with pytest.raises(LifecycleError, match="rolled back"):
        install_apt_hook(
            apt_conf_dir=apt, state_dir=state, python="/usr/bin/python3",
            effective_order_check=reject_order,
        )
    assert not (apt / HOOK_NAME).exists()
    assert not (state / STATE_NAME).exists()


def test_enable_rolls_back_when_effective_hook_order_is_unsafe(roots):
    apt, state = roots
    install_apt_hook(apt_conf_dir=apt, state_dir=state, python="/usr/bin/python3")
    disable_apt_hook(apt_conf_dir=apt, state_dir=state)

    def reject_order(python):
        raise LifecycleError("fixture has an earlier hook")

    with pytest.raises(LifecycleError, match="earlier hook"):
        enable_apt_hook(
            apt_conf_dir=apt, state_dir=state,
            effective_order_check=reject_order,
        )
    assert integration_status(apt_conf_dir=apt, state_dir=state)["status"] == "disabled"
    assert not (apt / HOOK_NAME).exists()


def test_atomic_publish_never_replaces_a_racing_existing_file(tmp_path):
    path = tmp_path / "managed.conf"
    path.write_text("administrator configuration\n")
    with pytest.raises(FileExistsError):
        _atomic_write(path, b"LinuxSecMonitor configuration\n", 0o644)
    assert path.read_text() == "administrator configuration\n"


def test_enable_rejects_occupied_path_and_corrupt_state(roots):
    apt, state = roots
    install_apt_hook(apt_conf_dir=apt, state_dir=state, python="/usr/bin/python3")
    disable_apt_hook(apt_conf_dir=apt, state_dir=state)
    (apt / HOOK_NAME).write_text("foreign\n")
    with pytest.raises(LifecycleError, match="occupied"):
        enable_apt_hook(apt_conf_dir=apt, state_dir=state)
    (apt / HOOK_NAME).unlink()
    (state / STATE_NAME).write_text(json.dumps({"format": 1}))
    with pytest.raises(LifecycleError, match="no recoverable Python"):
        enable_apt_hook(apt_conf_dir=apt, state_dir=state)


def test_symlink_hook_is_never_removed(roots, tmp_path):
    apt, state = roots
    victim = tmp_path / "other.conf"
    victim.write_text("preserve\n")
    (apt / HOOK_NAME).symlink_to(victim)
    with pytest.raises(LifecycleError):
        disable_apt_hook(apt_conf_dir=apt, state_dir=state)
    assert victim.read_text() == "preserve\n"


def test_trusted_runtime_rejects_user_writable_code_parent(tmp_path):
    interpreter = tmp_path / "bin/python"
    module = tmp_path / "lib/main.py"
    interpreter.parent.mkdir(parents=True)
    module.parent.mkdir(parents=True)
    interpreter.write_text("interpreter")
    interpreter.chmod(0o755)
    module.write_text("module")
    with pytest.raises(LifecycleError, match="not root-owned|writable by others"):
        validate_trusted_runtime(str(interpreter), (module,))


def test_hook_config_is_valid_apt_syntax_when_apt_config_is_available(roots):
    import shutil
    import subprocess

    apt_config = shutil.which("apt-config")
    if not apt_config:
        pytest.skip("apt-config is unavailable")
    apt, state = roots
    install_apt_hook(apt_conf_dir=apt, state_dir=state, python="/usr/bin/python3")
    completed = subprocess.run(
        [apt_config, "-c", str(apt / HOOK_NAME), "dump"],
        capture_output=True, text=True, timeout=5, check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert 'DPkg::Tools::Options::/usr/bin/python3::Version "3";' in completed.stdout
    assert "-m main --apt-preinstall-hook" in completed.stdout


def test_managed_dropin_precedes_later_preconfigure_and_main_config(tmp_path):
    import subprocess

    apt_config = Path("/usr/bin/apt-config")
    if not apt_config.is_file():
        pytest.skip("apt-config is unavailable")
    parts = tmp_path / "parts"
    parts.mkdir()
    hook = parts / HOOK_NAME
    hook.write_bytes(
        b'DPkg::Pre-Install-Pkgs { "/usr/bin/python3 -m main --apt-preinstall-hook"; };\n'
        b'DPkg::Tools::Options::/usr/bin/python3::Version "3";\n'
    )
    (parts / "70debconf").write_text(
        'DPkg::Pre-Install-Pkgs { "/usr/sbin/dpkg-preconfigure --apt"; };\n',
        encoding="utf-8",
    )
    main_config = tmp_path / "main.conf"
    main_config.write_text(
        'DPkg::Pre-Install-Pkgs { "/usr/bin/example-main-hook"; };\n',
        encoding="utf-8",
    )
    config = tmp_path / "apt-config.conf"
    config.write_text(
        f'Dir::Etc::Parts "{parts}";\nDir::Etc::main "{main_config}";\n',
        encoding="utf-8",
    )
    environment = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "APT_CONFIG": str(config), "LC_ALL": "C"}
    completed = subprocess.run(
        [str(apt_config), "dump"], capture_output=True, text=True,
        timeout=5, check=False, env=environment,
    )
    assert completed.returncode == 0, completed.stderr
    hooks = [
        line.split('"', 2)[1]
        for line in completed.stdout.splitlines()
        if line.startswith("DPkg::Pre-Install-Pkgs:: ")
    ]
    assert hooks == [
        "/usr/bin/python3 -m main --apt-preinstall-hook",
        "/usr/sbin/dpkg-preconfigure --apt",
        "/usr/bin/example-main-hook",
    ]
    validate_effective_hook_order(
        "/usr/bin/python3",
        environment={**environment, "APT_CONFIG": str(config)},
    )
    main_config.write_text("#clear DPkg::Pre-Install-Pkgs;\n", encoding="utf-8")
    with pytest.raises(LifecycleError, match="not the first effective"):
        validate_effective_hook_order(
            "/usr/bin/python3",
            environment={**environment, "APT_CONFIG": str(config)},
        )


@pytest.mark.parametrize(
    "python",
    ["relative/python", "/tmp/python;touch-pwned", "/tmp/$(touch-pwned)", "/tmp/python`id`"],
)
def test_hook_command_rejects_shell_metacharacters(python):
    from scanner.apt_lifecycle import hook_contents

    with pytest.raises(LifecycleError, match="absolute safe path"):
        hook_contents(python)
