from datetime import datetime, timezone


class DefaultCleaner:
    def validate(self, data):
        if not data:
            raise ValueError("Empty dataset")
        return data

    def normalize(self, data):
        normalized = []
        for row in data:
            normalized.append({
                k.strip().lower(): v.strip() if isinstance(v, str) else v
                for k, v in row.items()
            })
        return normalized

    def deduplicate(self, data):
        seen = set()
        unique = []

        for row in data:
            key = tuple(sorted(row.items()))
            if key not in seen:
                seen.add(key)
                unique.append(row)

        return unique

    def enrich(self, data):
        now = datetime.now(timezone.utc).isoformat()
        for row in data:
            row["ingested_at"] = now
        return data