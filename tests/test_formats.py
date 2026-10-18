from frx.flags.formats import (
    build_formats,
    compile_flag_regex,
    default_formats,
    parse_flag_format,
)


def test_parse_prefix_and_match():
    f = parse_flag_format("CTF{...}")
    assert f.prefix == "CTF{"
    assert f.regex.search(b"junk CTF{hello_world} junk")
    assert f.confirmed


def test_parse_without_wildcard_uses_brace():
    f = parse_flag_format("flag{")
    assert f.prefix == "flag{"
    assert f.regex.search(b"flag{abc}")


def test_body_excludes_closing_brace_and_newline():
    f = parse_flag_format("CTF{...}")
    m = f.regex.search(b"CTF{aaa}bbb}")
    assert m.group() == b"CTF{aaa}"


def test_flag_regex_is_verbatim_and_confirmed():
    f = compile_flag_regex(r"XX\{[0-9]+\}")
    assert f.confirmed
    assert f.prefix == "XX{"
    assert f.regex.search(b"XX{123}")
    assert not f.regex.search(b"XX{abc}")


def test_generic_default_is_unconfirmed():
    defs = default_formats()
    generic = [d for d in defs if not d.confirmed]
    assert len(generic) == 1
    assert generic[0].regex.search(b"somePrefix{body}")


def test_build_dedups_and_puts_user_first():
    fmts = build_formats(flag_formats=["CTF{...}"], include_defaults=True)
    # CTF{...} user format + flag{...} + generic, with the duplicate CTF default dropped
    sources = [f.source for f in fmts]
    assert sources[0] == "CTF{...}"
    # no two identical compiled patterns
    pats = [f.regex.pattern for f in fmts]
    assert len(pats) == len(set(pats))
