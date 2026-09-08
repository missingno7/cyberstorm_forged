# Decoded diagnostic dispatcher evidence

The extractor accepts a breadcrumb only when objdump decodes five physically contiguous instructions: push message; push immediate line; push source; direct call to the build-specific dispatcher; add esp,0xC. The message operand is recorded as immediate_string, immediate_unresolved, null, or dynamic.

June accepted patterns: 214.
Most common decoded direct target: 0x00477920 at 214 sites.

Representative validated site 0x00402349 is:
- push 0x0048400C, a literal message beginning invalid difficulty value;
- push 0x000001AC, line 428;
- push 0x00487FD0, shell\shell.c;
- call 0x00477920;
- add esp,0x0C.

GOG representative site 0x0040275F pushes invalid difficulty value, line 522, and source 0x0048E4DC; it calls 0x0047D5A0 and cleans 12 bytes. Its common target has the same observed dispatcher shape, including source, line, and message stack reads.

This establishes caller-cleaned 12-byte arguments at these sites: source pointer, 32-bit line word, message pointer. Under normal right-to-left x86 pushes, callee order is (source, line, message). Exact C types, return type, signedness, routine name, and translation unit remain unresolved. The June common target has a reentrancy guard, formatter call, MessageBox-like IAT call, guard clear, and normal epilogue. debug\assert.c is only a retained source-path literal, not ownership proof.