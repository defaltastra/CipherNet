#!/usr/bin/env python3
"""
CipherNet Main Entry Point
Network Security & Cryptography Interactive Desktop Application (PySide6).
"""

from __future__ import annotations
import argparse
import os
import sys
from pathlib import Path

# -------------------------------------------------------------
# Bootstrap Python path to support virtualenv and local imports
# -------------------------------------------------------------
CURRENT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = CURRENT_DIR.parent

# Add project root to sys.path
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# If .venv exists in project root, add its site-packages to sys.path
venv_site = PROJECT_ROOT / ".venv" / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages"
if venv_site.exists() and str(venv_site) not in sys.path:
    sys.path.insert(0, str(venv_site))


def main() -> int:
    """CLI parser and application launcher."""
    parser = argparse.ArgumentParser(
        prog="ciphernet",
        description="CipherNet – Network Security & Cryptography Desktop Dashboard (PySide6)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Created by Ilham Azra and Oussama El Harti.
Special thanks to https://github.com/ILHAMAZRA for her contribution.
GitHub Profiles:
  - Ilham Azra: https://github.com/ILHAMAZRA
  - Oussama El Harti: https://github.com/defaltastra
        """,
    )

    parser.add_argument(
        "-v", "--version",
        action="version",
        version="CipherNet 1.0.0 (by Ilham Azra & Oussama El Harti)",
    )

    parser.add_argument(
        "-c", "--config",
        type=str,
        default=None,
        help="Path to custom JSON configuration file.",
    )

    parser.add_argument(
        "--check-env",
        action="store_true",
        help="Verify dependencies and cryptographic capabilities.",
    )

    args = parser.parse_args()

    if args.check_env:
        print("Checking CipherNet PySide6 environment...")
        try:
            import PySide6
            import pyqtgraph
            import numpy
            import psutil
            import cryptography
            from PIL import Image

            crypto_ver = getattr(cryptography, "__version__", "installed")
            print(f"✔ PySide6 {PySide6.__version__}")
            print(f"✔ PyQtGraph {pyqtgraph.__version__}")
            print(f"✔ NumPy {numpy.__version__}")
            print(f"✔ psutil {psutil.__version__}")
            print(f"✔ cryptography {crypto_ver}")
            print(f"✔ Pillow {Image.__version__}")

            try:
                import scapy
                print(f"✔ Scapy {scapy.__version__} (Available for packet sniffing)")
            except ImportError:
                print("○ Scapy not installed (Optional packet sniffing disabled)")

            print("\nAll core dependencies verified successfully!")
            return 0
        except ImportError as ex:
            print(f"✖ Missing dependency: {ex}")
            return 1

    # Launch PySide6 Desktop Application
    try:
        from PySide6.QtWidgets import QApplication
        from ciphernet.app import CipherNetApp

        app = QApplication(sys.argv)
        app.setApplicationName("CipherNet")
        app.setApplicationDisplayName("CipherNet Security Dashboard")
        app.setOrganizationName("CipherNet")

        window = CipherNetApp(config_path=args.config)
        window.show()

        return app.exec()
    except KeyboardInterrupt:
        print("\n[CipherNet] Exiting cleanly. Goodbye!")
        return 0
    except Exception as ex:
        print(f"\n[CipherNet Error] An unexpected error occurred: {ex}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
