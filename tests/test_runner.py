import sys

from frx.engine.runner import Runner


def test_run_captures_stdout_and_command(tmp_path):
    r = Runner(tmp_path, nice=False)
    res = r.run([sys.executable, "-c", "print('hello')"])
    assert res.ok
    assert res.out_text().strip() == "hello"
    assert "hello" in res.command


def test_run_nonzero_returncode_is_not_ok(tmp_path):
    r = Runner(tmp_path, nice=False)
    res = r.run([sys.executable, "-c", "import sys; sys.exit(3)"])
    assert res.returncode == 3 and not res.ok


def test_missing_binary_returns_error_not_raises(tmp_path):
    r = Runner(tmp_path, nice=False)
    res = r.run(["this-binary-does-not-exist-frx"])
    assert not res.ok and res.error is not None


def test_timeout_is_flagged_and_killed(tmp_path):
    r = Runner(tmp_path, nice=False)
    res = r.run([sys.executable, "-c", "import time; time.sleep(30)"], timeout=0.5)
    assert res.timed_out and not res.ok
    assert res.duration < 10


def test_env_has_case_tmpdir_and_no_pyc(tmp_path):
    r = Runner(tmp_path, nice=False)
    res = r.run([sys.executable, "-c", "import os; print(os.environ['TMPDIR']); print(os.environ['PYTHONDONTWRITEBYTECODE'])"])
    lines = res.out_text().splitlines()
    assert lines[0].startswith(str(tmp_path))
    assert lines[1] == "1"


def test_input_bytes_are_piped(tmp_path):
    r = Runner(tmp_path, nice=False)
    res = r.run([sys.executable, "-c", "import sys; sys.stdout.write(sys.stdin.read().upper())"], input_bytes=b"abc")
    assert res.out_text() == "ABC"
