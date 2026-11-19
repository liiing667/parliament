class Finding:
    """Class for storing findings"""

    def __init__(self, issue, detail, location):
        self.issue = issue
        self.detail = detail
        # Each Finding gets its own location dict. Class-level mutable defaults
        # would otherwise share identity (and filepath attribution) across
        # policies audited in the same process.
        self.location = dict(location) if location else {}
        self.severity = ""
        self.title = ""
        self.description = ""
        self.ignore_locations = None

    def __repr__(self):
        """Return a string for printing"""
        return "{} - {} - {}".format(self.issue, self.detail, self.location)
