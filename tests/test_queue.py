from frx.engine.queue import WorkQueue, sha256_file


def _mk(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return p


def test_sha256_file(tmp_path):
    p = _mk(tmp_path, "a", b"abc")
    sha, size = sha256_file(p)
    assert size == 3
    assert sha == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_add_and_pop_fifo(tmp_path):
    q = WorkQueue()
    a = q.make_item(_mk(tmp_path, "a", b"a"), "other", 0, None, ["a"])
    b = q.make_item(_mk(tmp_path, "b", b"b"), "other", 0, None, ["b"])
    assert q.add(a) and q.add(b)
    assert q.pop().provenance == ["a"]
    assert q.pop().provenance == ["b"]
    assert q.pop() is None


def test_dedup_by_sha(tmp_path):
    q = WorkQueue()
    a = q.make_item(_mk(tmp_path, "a", b"same"), "other", 0, None, ["a"])
    b = q.make_item(_mk(tmp_path, "b", b"same"), "other", 1, "x", ["b"])
    assert q.add(a)
    assert not q.add(b, extracted=True)
    assert q.rejects.duplicate == 1


def test_depth_cap(tmp_path):
    q = WorkQueue(max_depth=2)
    deep = q.make_item(_mk(tmp_path, "d", b"deep"), "other", 3, "x", ["d"])
    assert not q.add(deep, extracted=True)
    assert q.rejects.depth == 1


def test_file_count_cap(tmp_path):
    q = WorkQueue(max_files=1)
    a = q.make_item(_mk(tmp_path, "a", b"a"), "other", 1, "x", ["a"])
    b = q.make_item(_mk(tmp_path, "b", b"b"), "other", 1, "x", ["b"])
    assert q.add(a, extracted=True)
    assert not q.add(b, extracted=True)
    assert q.rejects.files == 1


def test_size_cap(tmp_path):
    q = WorkQueue(max_extracted_size=4)
    a = q.make_item(_mk(tmp_path, "a", b"aaaa"), "other", 1, "x", ["a"])
    b = q.make_item(_mk(tmp_path, "b", b"b"), "other", 1, "x", ["b"])
    assert q.add(a, extracted=True)
    assert not q.add(b, extracted=True)
    assert q.rejects.size == 1


def test_original_inputs_bypass_file_cap(tmp_path):
    q = WorkQueue(max_files=0)
    a = q.make_item(_mk(tmp_path, "a", b"a"), "other", 0, None, ["a"])
    assert q.add(a, extracted=False)
