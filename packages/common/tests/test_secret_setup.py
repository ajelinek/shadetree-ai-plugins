import importlib
import importlib.util
import json

import keyring
import pytest
from shadetree_ai_plugins_common import secrets


def setup_module_under_test():
    name = "shadetree_ai_plugins_common.secret_setup"
    assert importlib.util.find_spec(name), "Shared hidden-prompt setup must exist"
    return importlib.import_module(name)


def memory_backend(monkeypatch):
    ring = {}

    class MemoryKeyring:
        def get_password(self, service, username):
            return ring.get((service, username))

        def set_password(self, service, username, password):
            ring[service, username] = password

        def delete_password(self, service, username):
            ring.pop((service, username), None)

    monkeypatch.setattr(secrets, "_secure_backend", lambda: MemoryKeyring(), raising=False)
    return ring


def test_hidden_setup_roundtrip_and_namespace_isolation(monkeypatch, capsys):
    module = setup_module_under_test()
    memory_backend(monkeypatch)
    monkeypatch.setattr(module.sys.stdin, "isatty", lambda: True)
    answers = iter(["fixture-secret", "fixture-secret"])
    monkeypatch.setattr(module.getpass, "getpass", lambda *args: next(answers))
    assert module.main(["set", "email-domain-reputation", "abstractapi-api-key"]) == 0
    assert secrets.get_secret("email-domain-reputation", "abstractapi-api-key") == "fixture-secret"
    assert secrets.get_secret("another-plugin", "abstractapi-api-key") is None
    assert module.main(["status", "email-domain-reputation", "abstractapi-api-key"]) == 0
    assert "fixture-secret" not in capsys.readouterr().out


def test_setup_refuses_noninteractive_secret_input(monkeypatch, capsys):
    module = setup_module_under_test()
    memory_backend(monkeypatch)
    monkeypatch.setattr(module.sys.stdin, "isatty", lambda: False)
    assert module.main(["set", "demo", "api-key"]) == 1
    assert "terminal" in capsys.readouterr().err.lower()
    assert secrets.get_secret("demo", "api-key") is None


def test_mismatched_confirmation_does_not_write(monkeypatch):
    module = setup_module_under_test()
    memory_backend(monkeypatch)
    monkeypatch.setattr(module.sys.stdin, "isatty", lambda: True)
    answers = iter(["fixture-secret", "different"])
    monkeypatch.setattr(module.getpass, "getpass", lambda *args: next(answers))
    assert module.main(["set", "demo", "api-key"]) == 1
    assert secrets.get_secret("demo", "api-key") is None


def test_set_cannot_silently_replace_existing_key(monkeypatch):
    module = setup_module_under_test()
    memory_backend(monkeypatch)
    secrets.set_secret("demo", "api-key", "original")
    assert module.main(["set", "demo", "api-key"]) == 1
    assert secrets.get_secret("demo", "api-key") == "original"


def test_backend_failure_never_echoes_secret(monkeypatch, capsys):
    module = setup_module_under_test()

    def fail():
        raise RuntimeError("fixture-secret")

    monkeypatch.setattr(secrets, "_secure_backend", fail, raising=False)
    assert module.main(["status", "demo", "api-key"]) == 1
    output = capsys.readouterr()
    assert "fixture-secret" not in output.out + output.err


def test_plaintext_or_missing_backend_is_rejected(monkeypatch):
    setup_module_under_test()
    monkeypatch.setattr(keyring, "get_keyring", lambda: keyring.backends.fail.Keyring())
    with pytest.raises(secrets.SecretStoreError):
        secrets.get_secret("demo", "api-key")


def test_status_is_machine_readable_and_never_contains_the_value(monkeypatch, capsys):
    module = setup_module_under_test()
    memory_backend(monkeypatch)
    secrets.set_secret("demo", "api-key", "fixture-secret")
    assert module.main(["status", "demo", "api-key"]) == 0
    assert json.loads(capsys.readouterr().out) == {"configured": True}


def test_set_file_stores_compact_json_and_offers_deletion(monkeypatch, tmp_path, capsys):
    module = setup_module_under_test()
    memory_backend(monkeypatch)
    monkeypatch.setattr(module.sys.stdin, "isatty", lambda: True)
    source = tmp_path / "key.json"
    source.write_text('{\n  "type": "service_account",\n  "private_key": "fixture"\n}\n')
    monkeypatch.setattr("builtins.input", lambda *args: "yes")
    assert module.main(["set-file", "demo", "sa", str(source)]) == 0
    stored = secrets.get_secret("demo", "sa")
    assert json.loads(stored) == {"type": "service_account", "private_key": "fixture"}
    assert " " not in stored and "\n" not in stored
    assert not source.exists()
    assert "fixture" not in capsys.readouterr().out


def test_set_file_rejects_invalid_json_and_keeps_file(monkeypatch, tmp_path):
    module = setup_module_under_test()
    memory_backend(monkeypatch)
    monkeypatch.setattr(module.sys.stdin, "isatty", lambda: True)
    source = tmp_path / "key.json"
    source.write_text("not json")
    assert module.main(["set-file", "demo", "sa", str(source)]) == 1
    assert secrets.get_secret("demo", "sa") is None
    assert source.exists()


def test_file_actions_require_a_path_and_plain_actions_refuse_one(monkeypatch):
    module = setup_module_under_test()
    memory_backend(monkeypatch)
    assert module.main(["set-file", "demo", "sa"]) == 1
    assert module.main(["status", "demo", "sa", "/tmp/x.json"]) == 1
