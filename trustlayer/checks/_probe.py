"""Resolution probe. Executed by the TARGET repository's interpreter, not TrustLayer's.

stdlib only, and no imports from `trustlayer`: this runs under whatever Python the audited
repository uses. Reads a JSON request on stdin, writes a JSON response on stdout.

Request:  {"modules": {"httpx": ["AsyncClient", "AsyncClientX"]}}
Response: {"httpx": {"found": true, "version": "0.27.0", "signatures": {...}, ...}}

`signatures` carries structured parameters - name, kind, has_default - rather than a
rendered string, so the caller never parses prose to decide a verdict. A callable only
appears there when it can be introspected with confidence; see `_signature_for`.

Importing a module executes its top-level code. This only imports modules that are already
installed in the target environment - the same trust level as running that repo's tests -
and never imports a module whose spec could not be found.
"""

import importlib
import importlib.metadata
import importlib.util
import inspect
import json
import sys
import typing


def describe(module_name, attributes):
    result = {
        "found": False,
        "stdlib": False,
        "version": None,
        "distribution": None,
        "location": None,
        "exports": [],
        "missing": [],
        "signatures": {},
        "import_error": None,
    }

    top_level = module_name.split(".")[0]
    if top_level in getattr(sys, "stdlib_module_names", frozenset()):
        result["stdlib"] = True
        result["distribution"] = "<stdlib>"

    try:
        spec = importlib.util.find_spec(module_name)
    except (ImportError, AttributeError, ValueError, TypeError):
        spec = None
    except Exception as error:  # noqa: BLE001 - a parent package executed and blew up
        result["import_error"] = f"{type(error).__name__}: {error}"
        return result

    if spec is None:
        return result

    result["found"] = True
    if getattr(spec, "origin", None):
        result["location"] = spec.origin

    if not result["stdlib"]:
        result["distribution"], result["version"] = _distribution_for(top_level)

    if not attributes:
        return result

    try:
        module = importlib.import_module(module_name)
    except BaseException as error:  # noqa: BLE001 - a bad module must not kill the probe
        result["import_error"] = f"{type(error).__name__}: {error}"
        return result

    result["exports"] = sorted(name for name in dir(module) if not name.startswith("_"))
    result["missing"] = [name for name in attributes if not hasattr(module, name)]

    for name in attributes:
        described = _signature_for(getattr(module, name, None))
        if described is not None:
            result["signatures"][name] = described
    return result


def _signature_for(obj):
    """Structured parameters for a plain Python function, or None to say "do not check".

    Deliberately narrow. Only `inspect.isfunction` objects qualify: pure-Python functions
    have reliable signatures, whereas C builtins frequently have none at all and classes
    drag in __new__, metaclasses and dataclass synthesis. Returning None means the caller
    stays silent, which is the correct outcome for everything this cannot be sure about.
    """
    if obj is None or not inspect.isfunction(obj):
        return None

    # An @overload-decorated function has several valid shapes and the runtime signature
    # is only the implementation, so any arity claim would be about the wrong one.
    try:
        if typing.get_overloads(obj):
            return None
    except Exception:  # noqa: BLE001 - get_overloads is best effort
        return None

    try:
        signature = inspect.signature(obj)
    except (TypeError, ValueError):
        return None

    return {
        "parameters": [
            {
                "name": parameter.name,
                "kind": parameter.kind.name,
                "has_default": parameter.default is not inspect.Parameter.empty,
            }
            for parameter in signature.parameters.values()
        ],
        "text": f"{obj.__name__}{signature}",
    }


def _distribution_for(top_level):
    try:
        mapping = importlib.metadata.packages_distributions()
    except Exception:  # noqa: BLE001 - older//patched importlib.metadata
        mapping = {}

    names = mapping.get(top_level) or []
    for name in names:
        try:
            return name, importlib.metadata.version(name)
        except Exception:  # noqa: BLE001, S112 - try the next distribution name
            continue

    try:  # the import name often equals the distribution name
        return top_level, importlib.metadata.version(top_level)
    except Exception:  # noqa: BLE001
        return (names[0] if names else None), None


def main():
    try:
        request = json.loads(sys.stdin.read() or "{}")
    except ValueError as error:
        json.dump({"__error__": f"bad request: {error}"}, sys.stdout)
        return 1

    modules = request.get("modules") or {}
    response = {
        "__python__": sys.version.split()[0],
        "__executable__": sys.executable,
        "modules": {name: describe(name, attrs) for name, attrs in modules.items()},
    }
    json.dump(response, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
