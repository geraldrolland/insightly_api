from abc import ABC, abstractmethod

class BaseCleaner(ABC):

    @abstractmethod
    def validate(self, data: list[dict]) -> list[dict]:
        pass

    @abstractmethod
    def normalize(self, data: list[dict]) -> list[dict]:
        pass

    @abstractmethod
    def deduplicate(self, data: list[dict]) -> list[dict]:
        pass

    @abstractmethod
    def enrich(self, data: list[dict]) -> list[dict]:
        pass

    def run(self, data: list[dict]) -> list[dict]:
        data = self.validate(data)
        data = self.normalize(data)
        data = self.deduplicate(data)
        data = self.enrich(data)
        return data