from typing import Callable, Dict

_REGISTRY: Dict[str, Callable] = {}

def provider_name(name: str):
    def deco(fn):
        _REGISTRY[name] = fn
        return fn
    return deco

def get_provider(name: str) -> Callable:
    return _REGISTRY[name]

def all_providers():
    return list(_REGISTRY.keys())
