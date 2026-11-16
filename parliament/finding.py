class Finding:
    """Class for storing findings"""

    def __init__(self, issue, detail, location):
        self.issue = issue
        self.detail = detail
        self.location = location
        self.severity = ""
        self.title = ""
        self.description = ""
        self.ignore_locations = None

    def __repr__(self):
        """Return a string for printing"""
        return "{} - {} - {}".format(self.issue, self.detail, self.location)
