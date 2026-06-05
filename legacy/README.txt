Legacy Versions
===============

These files are older monolithic builds of BB-RECON, kept for reference.

  bb-rec_legacy.py  — v6.0, single-file implementation, 10-step pipeline
  bb-recon.py       — v8.0, single-file implementation, ThreadPoolExecutor-based

The active codebase lives in:
  main.py           — entry point
  core/             — shared infrastructure
  modules/          — scan modules and scanners

Do not use these legacy files. Use `main.py` instead:
    python main.py -d example.com
