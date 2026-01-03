from .default import DefaultCleaner

class SchemaCleaner(DefaultCleaner):
    def __init__(self, schema: dict):
        self.schema = schema

    def validate(self, data):
        validated = []
        for row in data:
            new_row = {}
            for col, rules in self.schema.items():
                val = row.get(col)
                if val in [None, ""] and not rules["nullable"]:
                    raise ValueError(f"{col} cannot be null")
                # type conversion
                if rules["type"] == "int" and val not in [None, ""]:
                    val = int(val)
                elif rules["type"] == "float" and val not in [None, ""]:
                    val = float(val)
                new_row[col] = val
            validated.append(new_row)
        return validated