// Disable LeakSanitizer at build time (ASan stays on); Mayhem alone owns runtime ASAN/LSAN options.
extern "C" int __lsan_is_turned_off() { return 1; }
