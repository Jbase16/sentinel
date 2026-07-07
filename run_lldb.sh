#!/bin/bash
lldb ./ui/build/Debug/SentinelForge.app/Contents/MacOS/SentinelForge << 'LLDB_EOF'
run
quit
LLDB_EOF
