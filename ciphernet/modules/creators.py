"""
CipherNet Creators & Attribution Module (PySide6)
Showcases project creators (Ilham Azra and Oussama El Harti) with their
professional roles, research contributions, photographs, and GitHub links.
"""

from __future__ import annotations
from pathlib import Path
from typing import Optional
import webbrowser
from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from ciphernet.widgets.image_viewer import MediaViewerWidget
from ciphernet.widgets.panels import SectionHeader


PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


def open_url(url: str) -> None:
    """Opens a link in default browser."""
    try:
        QDesktopServices.openUrl(QUrl(url))
    except Exception:
        webbrowser.open(url)


class CreatorsView(QWidget):
    """
    Creators tribute and about page displaying bios, roles, media, and GitHub profiles.
    """

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._build_ui()

    def _find_asset(self, filename: str) -> Path:
        """Finds asset path in project root or ciphernet/assets/."""
        candidates = [
            PROJECT_ROOT / filename,
            PROJECT_ROOT / "ciphernet" / "assets" / filename,
            PROJECT_ROOT / "assets" / filename,
        ]
        for c in candidates:
            if c.exists():
                return c
        return PROJECT_ROOT / filename

    def _build_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(24, 20, 24, 20)
        main_layout.setSpacing(16)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setStyleSheet("QScrollArea { background: transparent; }")

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(20)

        # Top Header Banner
        banner = QHBoxLayout()
        banner.setContentsMargins(0, 0, 0, 0)
        header_col = QVBoxLayout()
        header_col.setSpacing(2)
        h_title = QLabel("PROJECT CREATORS & LEADERSHIP")
        h_title.setStyleSheet("color: #FFFFFF; font-size: 18px; font-weight: 900; letter-spacing: 0.5px;")
        h_sub = QLabel("Core Architecture, Threat Modeling & Open Source Collaboration Team")
        h_sub.setStyleSheet("color: #9CA3AF; font-size: 11px;")
        header_col.addWidget(h_title)
        header_col.addWidget(h_sub)
        banner.addLayout(header_col)
        banner.addStretch()
        layout.addLayout(banner)

        cards_row = QHBoxLayout()
        cards_row.setSpacing(24)

        # -------------------------------------------------------------
        # CREATOR 1: ILHAM AZRA
        # -------------------------------------------------------------
        ilham_card = QFrame()
        ilham_card.setProperty("class", "panel-card")
        ilham_card.setStyleSheet(
            "QFrame { background-color: #12141A; border: 1px solid #1E232E; border-radius: 12px; padding: 22px; }"
            "QFrame:hover { border: 1px solid rgba(255, 112, 166, 0.5); background-color: #151820; }"
        )
        ic_layout = QVBoxLayout(ilham_card)
        ic_layout.setSpacing(14)

        badge_ilham = QLabel("🛡️  SECURITY CONTRIBUTOR")
        badge_ilham.setStyleSheet(
            "background-color: rgba(255, 112, 166, 0.15); color: #FF70A6; "
            "border: 1px solid rgba(255, 112, 166, 0.4); border-radius: 12px; "
            "padding: 4px 12px; font-size: 10px; font-weight: 800; letter-spacing: 1px;"
        )
        badge_ilham.setAlignment(Qt.AlignCenter)
        ic_layout.addWidget(badge_ilham, 0, Qt.AlignCenter)

        # Image Viewer
        ilham_img_path = self._find_asset("ilham.jpg")
        ilham_media = MediaViewerWidget(ilham_img_path, max_width=210, max_height=210)
        ic_layout.addWidget(ilham_media, 0, Qt.AlignCenter)

        # Name & Title
        name_ilham = QLabel("ILHAM AZRA")
        name_ilham.setStyleSheet("color: #FFFFFF; font-size: 18px; font-weight: 900; letter-spacing: 1px;")
        name_ilham.setAlignment(Qt.AlignCenter)
        ic_layout.addWidget(name_ilham)

        role_ilham = QLabel("Threat Models & Attack Signature Design")
        role_ilham.setStyleSheet("color: #FF70A6; font-size: 12px; font-weight: 700;")
        role_ilham.setAlignment(Qt.AlignCenter)
        ic_layout.addWidget(role_ilham)

        # GitHub Button
        btn_gh_ilham = QPushButton("🌐 View GitHub Profile: @ILHAMAZRA")
        btn_gh_ilham.setProperty("class", "btn-primary")
        btn_gh_ilham.clicked.connect(lambda: open_url("https://github.com/ILHAMAZRA"))
        ic_layout.addWidget(btn_gh_ilham)

        # Bio details
        bio_ilham = QLabel(
            "<div style='color: #9CA3AF; font-size: 12px; line-height: 1.6;'>"
            "<b style='color: #F3F4F6;'>Key Contributions & Research:</b><br>"
            "• Co-conceptualized the CipherNet cybersecurity vision.<br>"
            "• Designed threat model profiles & intrusion detection signatures.<br>"
            "• Formulated simulation scenarios for reconnaissance sweeps.<br>"
            "• Shaped visual design aesthetics & cyberpunk color palettes.<br><br>"
            "<i style='color: #FF70A6;'>Special thanks to <b>https://github.com/ILHAMAZRA</b> for her contribution!</i>"
            "</div>"
        )
        bio_ilham.setTextFormat(Qt.RichText)
        bio_ilham.setWordWrap(True)
        ic_layout.addWidget(bio_ilham)
        ic_layout.addStretch()

        cards_row.addWidget(ilham_card, 1)

        # -------------------------------------------------------------
        # CREATOR 2: OUSSAMA EL HARTI
        # -------------------------------------------------------------
        oussama_card = QFrame()
        oussama_card.setProperty("class", "panel-card")
        oussama_card.setStyleSheet(
            "QFrame { background-color: #12141A; border: 1px solid #1E232E; border-radius: 12px; padding: 22px; }"
            "QFrame:hover { border: 1px solid rgba(255, 112, 166, 0.5); background-color: #151820; }"
        )
        oc_layout = QVBoxLayout(oussama_card)
        oc_layout.setSpacing(14)

        badge_oussama = QLabel("⚡  SYSTEMS ARCHITECT")
        badge_oussama.setStyleSheet(
            "background-color: rgba(78, 204, 163, 0.15); color: #4ECCA3; "
            "border: 1px solid rgba(78, 204, 163, 0.4); border-radius: 12px; "
            "padding: 4px 12px; font-size: 10px; font-weight: 800; letter-spacing: 1px;"
        )
        badge_oussama.setAlignment(Qt.AlignCenter)
        oc_layout.addWidget(badge_oussama, 0, Qt.AlignCenter)

        # GIF / Image Viewer
        oussama_img_path = self._find_asset("oussama.gif")
        oussama_media = MediaViewerWidget(oussama_img_path, max_width=210, max_height=210)
        oc_layout.addWidget(oussama_media, 0, Qt.AlignCenter)

        # Name & Title
        name_oussama = QLabel("OUSSAMA EL HARTI")
        name_oussama.setStyleSheet("color: #FFFFFF; font-size: 18px; font-weight: 900; letter-spacing: 1px;")
        name_oussama.setAlignment(Qt.AlignCenter)
        oc_layout.addWidget(name_oussama)

        role_oussama = QLabel("Desktop Framework & Cryptography Lab")
        role_oussama.setStyleSheet("color: #4ECCA3; font-size: 12px; font-weight: 700;")
        role_oussama.setAlignment(Qt.AlignCenter)
        oc_layout.addWidget(role_oussama)

        # GitHub Button
        btn_gh_oussama = QPushButton("🌐 View GitHub Profile: @defaltastra")
        btn_gh_oussama.setProperty("class", "btn-primary")
        btn_gh_oussama.clicked.connect(lambda: open_url("https://github.com/defaltastra"))
        oc_layout.addWidget(btn_gh_oussama)

        # Bio details
        bio_oussama = QLabel(
            "<div style='color: #9CA3AF; font-size: 12px; line-height: 1.6;'>"
            "<b style='color: #F3F4F6;'>Key Contributions & Architecture:</b><br>"
            "• Architected the standalone PySide6 Qt GUI & asynchronous workers.<br>"
            "• Engineered real-time socket telemetry & traffic rate meters.<br>"
            "• Implemented cryptography lab (AES-256-GCM, RSA-PSS, SHA-256).<br>"
            "• Designed dark charcoal theme with rose accents and hotkey bindings.<br><br>"
            "<i style='color: #83A598;'>Visit profile: <b>https://github.com/defaltastra</b></i>"
            "</div>"
        )
        bio_oussama.setTextFormat(Qt.RichText)
        bio_oussama.setWordWrap(True)
        oc_layout.addWidget(bio_oussama)
        oc_layout.addStretch()

        cards_row.addWidget(oussama_card, 1)

        layout.addLayout(cards_row)

        # -------------------------------------------------------------
        # Project Vision & License Box
        # -------------------------------------------------------------
        layout.addWidget(SectionHeader("About CipherNet", "Philosophy & Open Source License"))

        about_card = QFrame()
        about_card.setProperty("class", "panel-card")
        about_card.setStyleSheet("QFrame { background-color: #12141A; border: 1px solid #1E232E; border-radius: 10px; padding: 18px; }")
        ac_layout = QVBoxLayout(about_card)

        about_text = QLabel(
            "<div style='color: #D1D5DB; font-size: 12px; line-height: 1.7;'>"
            "<b>CipherNet</b> is an interactive cybersecurity dashboard engineered for security analysts, developers, and enthusiasts.<br>"
            "Combines real-time network observation, rule-based intrusion simulation, and standard cryptographic primitives in a modern standalone desktop interface.<br><br>"
            "<b style='color: #9CA3AF;'>Creators:</b> &nbsp;Ilham Azra (<a style='color: #FF70A6;' href='https://github.com/ILHAMAZRA'>https://github.com/ILHAMAZRA</a>) and "
            "Oussama El Harti (<a style='color: #FF70A6;' href='https://github.com/defaltastra'>https://github.com/defaltastra</a>)<br>"
            "<b style='color: #9CA3AF;'>License:</b> &nbsp;<span style='color: #4ECCA3;'>MIT License — Copyright (c) 2026 Ilham Azra & Oussama El Harti.</span>"
            "</div>"
        )
        about_text.setTextFormat(Qt.RichText)
        about_text.setOpenExternalLinks(True)
        ac_layout.addWidget(about_text)

        layout.addWidget(about_card)
        layout.addStretch()

        scroll.setWidget(container)
        main_layout.addWidget(scroll)
