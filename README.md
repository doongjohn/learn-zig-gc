# Simple Mark and Sweep GC

1. Keeps track of allocated pointers.
2. Scan `.data`, `.bss`, and `stack` region for the potential pointers.
3. Mark all pointers. (Also traverse nested pointers.)
4. Sweep all unmarked pointers.
