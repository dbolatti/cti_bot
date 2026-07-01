#!/usr/bin/env python3
"""Bloquea commits que incluyan archivos sensibles (credenciales, DB local).

Corre como hook de pre-commit, en paralelo a detect-secrets: este script
bloquea por nombre de archivo (defensa adicional aunque .gitignore falle
o alguien use `git add -f`), detect-secrets bloquea por contenido.
"""
import subprocess
import sys

BLOCKED_NAMES = {".env", "cti.db"}


def staged_files() -> list[str]:
    out = subprocess.run(
        ["git", "diff", "--cached", "--name-only"],
        capture_output=True, text=True, check=True,
    ).stdout
    return [f for f in out.splitlines() if f]


def main() -> int:
    blocked = [f for f in staged_files() if f.split("/")[-1] in BLOCKED_NAMES]
    if blocked:
        print("ERROR: intentando commitear archivo(s) sensible(s):")
        for f in blocked:
            print(f"  - {f}")
        print("Sacalo del staging con: git restore --staged <archivo>")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
