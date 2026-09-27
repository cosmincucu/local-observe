import sys

from .cli import main

sys.stdout.reconfigure(encoding='utf-8', errors='replace')
raise SystemExit(main())
