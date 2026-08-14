"""Medium severity only: a swallowed exception, no high-severity defect."""


def load(path):
    try:
        return open(path).read()
    except Exception:
        pass
