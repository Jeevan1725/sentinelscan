"""FastMCP tool server for SentinelScan."""
from fastmcp import FastMCP
from .. import analyzer


def scan_artifact(code: str):
    """Scan code text for malicious behaviors (static analysis)."""
    return {"behaviors": analyzer.detect_behaviors(code)}


def extract_indicators(code: str):
    """Extract IOCs (URLs, IPs, emails) from code text."""
    return {"iocs": analyzer.extract_iocs(code)}


def classify_artifact(name: str):
    """Classify artifact type from filename."""
    return {"artifact_type": analyzer.classify_artifact(name, "")}


def scan_secrets(code: str):
    """Detect and redact secrets in code (AWS keys, tokens, private keys)."""
    return {"secrets": analyzer.scan_secrets(code)}


def _serve():
    mcp = FastMCP("sentinelscan-tools")

    @mcp.tool()
    def scan_artifact_tool(code: str):
        """Scan code text for malicious behaviors."""
        return scan_artifact(code)

    @mcp.tool()
    def extract_indicators_tool(code: str):
        """Extract IOCs from code text."""
        return extract_indicators(code)

    @mcp.tool()
    def classify_artifact_tool(name: str):
        """Classify artifact type from filename."""
        return classify_artifact(name)

    @mcp.tool()
    def scan_secrets_tool(code: str):
        """Detect and redact secrets in code."""
        return scan_secrets(code)

    mcp.run()


if __name__ == "__main__":
    _serve()
