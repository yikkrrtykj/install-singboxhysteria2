CR = chr(13)
BS = chr(92)
P = "tests/test-monitor-v2-m2.sh"
src = open(P, encoding="utf-8").read()
broken = "tr -d '" + CR + "'"
fixed = "tr -d '" + BS + "r'"
assert broken in src, "broken tr not found"
src = src.replace(broken, fixed)
open(P, "w", encoding="utf-8").write(src)
print("tr fixed")
