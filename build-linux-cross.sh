#!/bin/bash
# Cross-compiles the WINDOWS build of Kaevex from Linux (MinGW-w64) WITH its resources
# (manifest, icon, bitmaps), runs the portable unit tests, and writes release/windows/kaevex.exe
set -e
cd "$(dirname "$0")"
mkdir -p release/windows /tmp/kvx-build
for t in ai_core fw_core link_core ledger cve_core waf_core; do gcc -pthread -Wall -Wno-unused -Wno-format-truncation -Wno-misleading-indentation -fsanitize=address,undefined -o /tmp/kvx-build/t_$t tests/test_$t.c && printf "%-9s" $t && /tmp/kvx-build/t_$t | tail -1; done
# windres cannot read the backslash paths used by build.bat's resource script
sed -e 's#src\\\\kaevex.manifest#src/kaevex.manifest#' -e 's#assets\\\\#assets/#g' src/kaevex.rc > /tmp/kvx-build/kaevex_lin.rc
x86_64-w64-mingw32-windres -I. -i /tmp/kvx-build/kaevex_lin.rc -o /tmp/kvx-build/kaevex_res.o
x86_64-w64-mingw32-gcc -mwindows -O2 -w -I src/engines -o release/windows/kaevex.exe src/main.c src/gui/kaevex-gui.c src/cli/kaevex-cli.c /tmp/kvx-build/kaevex_res.o \
  -lcomctl32 -lws2_32 -liphlpapi -lshell32 -lole32 -loleaut32 -luuid -lcomdlg32 -lcrypt32 -lpsapi -ldwmapi -luxtheme -lwinhttp -lshlwapi -lntdll -ladvapi32 -luser32 -lgdi32 -lwinmm -lwintrust -licmp
echo "built release/windows/kaevex.exe ($(du -h release/windows/kaevex.exe | cut -f1))"
