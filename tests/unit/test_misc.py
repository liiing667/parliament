import jsoncfg

from parliament.misc import normalize_location


class TestNormalizeLocation:
    def setup_method(self):
        self.config = jsoncfg.loads_config(
            """{
    "Version": "2012-10-17",
    "Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}
}"""
        )

    def test_tuple_location(self):
        location = normalize_location(("Bogus", self.config["Version"]))
        assert location == {
            "string": "Bogus",
            "line": 2,
            "column": 16,
        }

    def test_scalar_location(self):
        location = normalize_location(self.config["Version"])
        assert location == {
            "string": "2012-10-17",
            "line": 2,
            "column": 16,
        }

    def test_object_location(self):
        location = normalize_location(self.config["Statement"])
        assert location == {"line": 3, "column": 18}

    def test_nested_scalar_location(self):
        location = normalize_location({"string": self.config["Version"]})
        assert location == {
            "string": "2012-10-17",
            "line": 2,
            "column": 16,
        }

    def test_nested_tuple_location(self):
        location = normalize_location(
            {"string": ("Bogus", self.config["Version"])}
        )
        assert location == {
            "string": "Bogus",
            "line": 2,
            "column": 16,
        }

    def test_nested_object_location_keeps_location(self):
        location = normalize_location({"string": self.config["Statement"]})
        assert location["line"] == 3
        assert location["column"] == 18

    def test_plain_dict_location_is_preserved(self):
        location = normalize_location({"action": "s3:GetObject"})
        assert location == {"action": "s3:GetObject"}
