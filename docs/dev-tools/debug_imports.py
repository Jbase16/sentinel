"""Module debug_imports: inline documentation for /Users/jason/Developer/sentinelforge/debug_imports.py."""

try:
    from core.cortex.events import get_event_bus
    print("Found get_event_bus in core.cortex.events")
except ImportError:
    print("FAILED to find get_event_bus in core.cortex.events")

try:
    from core.cortex.events import EventStore
    print("Found EventStore in core.cortex.events")
except ImportError:
    print("FAILED to find EventStore in core.cortex.events")

import os
# helper to find where EventStore might be
print("Searching for EventStore string in core...")
os.system("grep -r 'class EventStore' core")
