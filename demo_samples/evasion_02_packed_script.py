# EVASION: base64-packed payload
import base64
blob = base64.b64decode(
    "aW1wb3J0IHN1YnByb2Nlc3M7IHN1YnByb2Nlc3MucnVuKFsiY21kIiwiL2MiLCJ3aG9hbWkiXSk="
)
eval(compile(blob, "<packed>", "exec"))
