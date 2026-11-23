"""mitmdump script entry point. Logic lives in hobgoblin.enforcer (an ordinary
module, so it is imported normally rather than through the script loader)."""

from hobgoblin.enforcer import Hobgoblin

addons = [Hobgoblin()]
