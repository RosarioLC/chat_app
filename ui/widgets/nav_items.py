from textual.widgets import Static

# Mapping from binding keys to app action names.
_ACTION_MAP: dict[str, str] = {
    "h": "home",
    "s": "search",
    "l": "library",
}


class NavItem(Static):
    """Clickable navigation item in the sidebar."""

    def __init__(self, label: str, binding: str) -> None:
        """Initialize the nav item.

        Args:
            label: Display text.
            binding: Keyboard binding key (e.g. "h", "s", "l").
        """
        super().__init__(f"{label}", classes="nav-item")
        self._label = label
        self._binding = binding

    async def on_click(self) -> None:
        """Navigate to the corresponding screen."""
        action = _ACTION_MAP.get(self._binding)
        if action and self.app:
            await self.app.run_action(f"go_{action}")
