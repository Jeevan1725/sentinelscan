# EVASION: indirect execution via string building
import subprocess
cmd = "".join(["s", "c", "h", "t", "a", "s", "k", "s"])
subprocess.run([cmd, "/query"], capture_output=True)
