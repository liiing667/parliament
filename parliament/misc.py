import jsoncfg


def normalize_location(location):
    """
    Convert the different shapes used for a finding location into a plain dict.

    jsoncfg nodes cannot be mutated directly, so any ConfigJSONScalar,
    ConfigJSONObject or (key, node) tuple must be translated before the
    location is attached to a Finding.
    """
    type_name = str(type(location))

    # A jsoncfg object/array node
    if "jsoncfg.config_classes.ConfigJSON" in type_name and "Scalar" not in type_name:
        node_location = jsoncfg.node_location(location)
        return {"line": node_location.line, "column": node_location.column}

    # A jsoncfg scalar node
    if "ConfigJSONScalar" in type_name:
        node_location = jsoncfg.node_location(location)
        return {
            "string": location.value,
            "line": node_location.line,
            "column": node_location.column,
        }

    # A plain (key, node) tuple
    if isinstance(location, tuple):
        node_location = jsoncfg.node_location(location[1])
        return {
            "string": location[0],
            "line": node_location.line,
            "column": node_location.column,
        }

    if not isinstance(location, dict):
        return {"string": location}

    if "string" not in location:
        return location

    node = location["string"]
    node_type_name = str(type(node))

    # A (key, node) tuple nested under the "string" key
    if isinstance(node, tuple):
        node_location = jsoncfg.node_location(node[1])
        location["string"] = node[0]
        location["line"] = node_location.line
        location["column"] = node_location.column
        return location

    # A jsoncfg scalar nested under the "string" key
    if "ConfigJSONScalar" in node_type_name:
        node_location = jsoncfg.node_location(node)
        location["string"] = node.value
        location["line"] = node_location.line
        location["column"] = node_location.column
        return location

    # A jsoncfg object/array nested under the "string" key
    if "jsoncfg.config_classes" in node_type_name:
        node_location = jsoncfg.node_location(node)
        location["line"] = node_location.line
        location["column"] = node_location.column
        return location

    return location


def make_list(v):
    """
    If the object is not a list already, it converts it to one
    Examples:
    [1, 2, 3] -> [1, 2, 3]
    [1] -> [1]
    1 -> [1]
    """
    if not jsoncfg.node_is_array(v):
        if jsoncfg.node_is_scalar(v):
            location = jsoncfg.node_location(v)
            line = location.line
            column = location.column
        elif jsoncfg.node_exists(v):
            line = v.line
            column = v.column
        else:
            return []

        a = jsoncfg.config_classes.ConfigJSONArray(line, column)
        a._append(v)
        return a
    return v


class ACCESS_DECISION:
    IMPLICIT_DENY = 0
    EXPLICIT_DENY = 1
    EXPLICIT_ALLOW = 2
