"""
CipherNet Photographic and Media Viewer Widget
Renders photographic images and animated GIFs using native PySide6
QPixmap and QMovie components with cyber card borders and rounded corners.
"""

from __future__ import annotations
from pathlib import Path
from typing import Optional
from PySide6.QtCore import Qt, QSize
from PySide6.QtGui import QMovie, QPixmap
from PySide6.QtWidgets import (
    QFrame,
    QLabel,
    QVBoxLayout,
    QWidget,
)


class MediaViewerWidget(QFrame):
    """
    Renders high-fidelity images (JPEG, PNG) or animated GIFs
    with a dark charcoal frame and subtle rose border.
    """

    def __init__(
        self,
        image_path: str | Path,
        max_width: int = 220,
        max_height: int = 220,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.image_path = Path(image_path)
        self.max_width = max_width
        self.max_height = max_height
        self.movie: Optional[QMovie] = None

        self.setStyleSheet(
            "QFrame { background-color: #16171B; border: 1px solid #2D3139; border-radius: 8px; padding: 4px; }"
            "QFrame:hover { border: 1px solid #FF70A6; }"
        )

        layout = QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)

        self.image_label = QLabel()
        self.image_label.setAlignment(Qt.AlignCenter)
        self.image_label.setStyleSheet("border: none; background: transparent;")
        layout.addWidget(self.image_label)

        self.load_media()

    def load_media(self) -> None:
        if not self.image_path.exists():
            self.image_label.setText(f"[ Missing media:\n{self.image_path.name} ]")
            self.image_label.setStyleSheet("color: #FF4D6D; font-size: 11px;")
            return

        suffix = self.image_path.suffix.lower()
        if suffix == ".gif":
            self.movie = QMovie(str(self.image_path))
            if self.movie.isValid():
                self.movie.setScaledSize(QSize(self.max_width, self.max_height))
                self.image_label.setMovie(self.movie)
                self.movie.start()
                return

        # Fallback to QPixmap for JPG/PNG or non-animated files
        pixmap = QPixmap(str(self.image_path))
        if not pixmap.isNull():
            scaled = pixmap.scaled(
                self.max_width,
                self.max_height,
                Qt.KeepAspectRatio,
                Qt.SmoothTransformation,
            )
            self.image_label.setPixmap(scaled)
        else:
            self.image_label.setText(f"[ Unreadable:\n{self.image_path.name} ]")
            self.image_label.setStyleSheet("color: #FABD2F; font-size: 11px;")
