import logging
import os
import re
from pathlib import Path

logger = logging.getLogger(__name__)

# ==========================================
# FILE TYPES AND DIRECTORIES
# ==========================================

SUPPORTED_EXTENSIONS = {
    ".py", ".java", ".js", ".ts", ".jsx", ".tsx",
    ".cs", ".json", ".txt", ".env", ".yaml",
    ".yml", ".ini", ".cfg", ".properties",
    ".xml", ".toml", ".sh", ".ps1", ".config"
}

SPECIAL_FILENAMES = {
    ".env", ".npmrc", ".pypirc", "dockerfile"
}

SKIP_DIRECTORIES = {
    ".git", "__pycache__", "node_modules",
    ".venv", "venv", ".idea", ".pytest_cache"
}

# ==========================================
# SECRET DETECTION PATTERNS
# ==========================================

# Pattern for quoted credentials assigned
# with = or : in common code/configuration.
#
# Backreference \2 ensures the closing quote
# matches the opening quote.

CREDENTIAL_REGEX = re.compile(
    r"""(?i)(?<![\w])"""
    r"""((?:[\w-]*password|passwd|pwd|"""
    r"""[\w-]*api[_-]?key|apikey|"""
    r"""client[_-]?secret|secret[_-]?key|"""
    r"""[\w-]*token))"""
    r"""\s*["']?\s*[:=]\s*(["'])"""
    r"""([^"'\r\n]+)\2"""
)

AWS_REGEX = re.compile(
    r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"
)

GITHUB_REGEX = re.compile(
    r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b"
)

PRIVATE_KEY_REGEX = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |"
    r"ENCRYPTED )?PRIVATE KEY-----"
)

# ==========================================
# DETECTION FUNCTIONS
# ==========================================

def classify_credential(name):
    name = name.lower().replace("-", "_")

    if "password" in name or name.endswith(
        ("passwd", "pwd")
    ):
        return "Password"

    if "token" in name:
        return "Token"

    return "API Key"


def detect_secrets(text):
    """
    Detect potential hardcoded credentials.

    Returns dictionaries containing:
    type, match, and column.
    """
    findings = []

    # Detect credential assignments
    for match in CREDENTIAL_REGEX.finditer(text):
        variable = match.group(1)

        findings.append({
            "type": classify_credential(variable),
            "match": match.group(0),
            "column": match.start() + 1
        })

    # Detect recognizable provider formats
    patterns = {
        "AWS Access Key": AWS_REGEX,
        "GitHub Token": GITHUB_REGEX,
        "Private Key": PRIVATE_KEY_REGEX
    }

    for secret_type, pattern in patterns.items():
        for match in pattern.finditer(text):
            findings.append({
                "type": secret_type,
                "match": match.group(0),
                "column": match.start() + 1
            })

    # Remove exact duplicate locations/matches
    unique = []
    seen = set()

    for finding in findings:
        identifier = (
            finding["column"],
            finding["match"]
        )

        if identifier not in seen:
            unique.append(finding)
            seen.add(identifier)

    return sorted(
        unique,
        key=lambda item: item["column"]
    )


# ==========================================
# MASK SENSITIVE INFORMATION
# ==========================================

def mask_secret(matched_text):
    """
    Mask a credential before displaying
    or exporting it.
    """
    if "-----BEGIN" in matched_text:
        return "[PRIVATE KEY DETECTED]"

    assignment = re.match(
        r"""([\w-]+\s*["']?\s*[:=])""",
        matched_text
    )

    if assignment:
        return assignment.group(1) + " ********"

    return "[REDACTED SECRET]"


# ==========================================
# FILE VALIDATION
# ==========================================

def is_supported_file(file_path):
    file_path = Path(file_path)
    name = file_path.name.lower()

    return (
        file_path.suffix.lower() in SUPPORTED_EXTENSIONS
        or name in SPECIAL_FILENAMES
        or name.startswith(".env.")
    )


# ==========================================
# SINGLE FILE SCANNING
# ==========================================

def scan_file(file_path):
    """
    Read a file line by line and return
    any potential hardcoded secrets.
    """
    file_path = Path(file_path)
    findings = []

    logger.info("Scanning: %s", file_path)

    try:
        with file_path.open(
            "r",
            encoding="utf-8",
            errors="replace"
        ) as file:

            for line_number, line in enumerate(
                file, start=1
            ):
                matches = detect_secrets(line)

                for match in matches:
                    findings.append({
                        "file": str(file_path),
                        "line": line_number,
                        "column": match["column"],
                        "type": match["type"],
                        "match": match["match"]
                    })

    except OSError as error:
        logger.warning(
            "Unable to read %s: %s",
            file_path, error
        )

    return findings


# ==========================================
# FILE AND DIRECTORY SCANNING
# ==========================================

def scan_path(target_path, exclude_paths=None):
    """
    Scan one file or recursively scan
    a directory of supported files.
    """
    target = Path(target_path).expanduser()

    if not target.exists():
        raise FileNotFoundError(
            f"Path does not exist: {target}"
        )

    excluded = {
        Path(path).resolve()
        for path in (exclude_paths or [])
    }

    findings = []

    if target.is_file():
        if target.resolve() not in excluded:
            return scan_file(target)
        return []

    if not target.is_dir():
        raise ValueError("Target must be a file or directory.")

    for folder, directories, filenames in os.walk(
        target, followlinks=False
    ):
        directories[:] = [
            name for name in directories
            if name not in SKIP_DIRECTORIES
            and not (Path(folder) / name).is_symlink()
        ]

        for filename in filenames:
            file_path = Path(folder) / filename

            if file_path.is_symlink():
                continue

            if file_path.resolve() in excluded:
                continue

            if not is_supported_file(file_path):
                continue

            findings.extend(scan_file(file_path))

    return findings


# ==========================================
# DIRECT TESTING
# ==========================================

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s: %(message)s"
    )

    target = Path(__file__).with_name(
        "test_secrets.txt"
    )

    if not target.exists():
        print("Create test_secrets.txt first.")
    else:
        results = scan_path(target)

        print("\nSECRETGUARD SCANNER")
        print("=" * 35)
        print(f"Potential secrets: {len(results)}")

        for finding in results:
            print(
                f"\nFile: {finding['file']}"
                f"\nLine: {finding['line']}"
                f"\nType: {finding['type']}"
                f"\nMatch: {mask_secret(finding['match'])}"
            )
