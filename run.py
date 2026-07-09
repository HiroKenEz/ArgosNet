"""Lanceur racine d'ArgosNet (utilisé comme point d'entrée du packaging)."""
import sys

from argosnet.main import main

if __name__ == "__main__":
    sys.exit(main())
