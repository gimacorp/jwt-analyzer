"""Report renderers for the JWT analyzer."""

from .console import render_console
from .html_report import render_html

__all__ = ["render_console", "render_html"]
