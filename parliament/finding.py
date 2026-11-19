class Finding:
    """Class for storing findings"""

    issue = ""
    detail = ""
    location = {}
    severity = ""
    title = ""
    description = ""
    ignore_locations = {}

    def __init__(self, issue, detail, location):
        self.issue = issue
        self.detail = detail
        self.location = location

    def __repr__(self):
        """Return a string for printing"""
        return "{} - {} - {}".format(self.issue, self.detail, self.location)

    @property
    def identity(self):
        """Stable identifier of the underlying problem this finding reports.

        Two findings describe the same problem if they have the same issue,
        the same detail, and the same location. Reporting/auditing paths must
        never change that identity, so severity, title, description and
        ignore configuration are intentionally not part of it.
        """
        return (self.issue, _freeze(self.detail), _freeze(self.location))

    def __eq__(self, other):
        if not isinstance(other, Finding):
            return NotImplemented
        return self.identity == other.identity

    def __hash__(self):
        return hash(self.identity)


def _freeze(value):
    """Convert a (possibly nested) dict/list into a hashable structure."""
    if isinstance(value, dict):
        return tuple((key, _freeze(value[key])) for key in sorted(value, key=str))
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, set):
        return tuple(sorted((_freeze(item) for item in value), key=str))
    return value


def dedupe_findings(findings):
    """Collapse findings that report the exact same problem to one entry.

    The first occurrence wins so that ordering stays deterministic across
    auditors, reporters and CLI output formats.
    """
    unique_findings = []
    seen_identities = set()
    for finding in findings:
        identity = finding.identity
        if identity in seen_identities:
            continue
        seen_identities.add(identity)
        unique_findings.append(finding)
    return unique_findings
