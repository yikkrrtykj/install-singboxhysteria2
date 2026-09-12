import io

p = "tests/test-monitor-packaging.sh"
s = io.open(p, encoding="utf-8", newline="").read()
BS = chr(92)
NL = BS + "n"  # literal backslash-n as it appears in the file

def rep(old, new, tag):
    global s
    assert old in s, "pattern not found: " + tag
    s = s.replace(old, new, 1)

old1 = '        echo "$((n - 1))" > "' + BS + '$MOCK_FAIL_IS_ACTIVE_COUNT"'
new1 = '        echo "' + BS + '$((n - 1))" > "' + BS + '$MOCK_FAIL_IS_ACTIVE_COUNT"'
rep(old1, new1, "is-active counter echo")

old2 = ("        printf '--- install output (rc=%s) " + NL + "' \"$rc\" >&2\n"
        "        cat -- \"$out\" >&2\n"
        "        printf '--- end install output " + NL + "' >&2")
new2 = ("        printf '%s" + NL + "' \"--- install output (rc=$rc) ---\" >&2\n"
        "        cat -- \"$out\" >&2\n"
        "        printf '%s" + NL + "' \"--- end install output ---\" >&2")
rep(old2, new2, "printf dump")

io.open(p, "w", encoding="utf-8", newline="\n").write(s)
print("fixed OK")
