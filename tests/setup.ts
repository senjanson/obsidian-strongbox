// The plugin reaches timers and the like through `window`, as Obsidian's
// renderer has it. In Node the global object stands in for it.
(globalThis as any).window ??= globalThis;
