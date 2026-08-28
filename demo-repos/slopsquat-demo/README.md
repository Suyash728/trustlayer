# slopsquat-demo

A small service whose `requirements.txt` looks completely ordinary and is not.

Six dependencies. Three are fine. The other three are each wrong in a different way, and no
amount of reading `app.py` would tell you which is which — the code imports the packages it
means to import. The defect is in the dependency list, which is exactly the artifact an LLM
writes fastest and a reviewer reads slowest.

```sh
uv run trustlayer deps demo-repos/slopsquat-demo
```

| Dependency | What it is |
|---|---|
| `requests`, `fastapi`, `python-dotenv` | Real, popular, correct. Scored 0 and reported as nothing. |
| `reqeusts` | Does not exist on PyPI. One edit from `requests`. Anyone can register it. |
| `langchain-comunity` | Does not exist on PyPI. One edit from `langchain-community`. |
| `beautifulsoup` | **Real, and still wrong.** The package you want is `beautifulsoup4`. |

That last row is the one worth understanding. `beautifulsoup` is a genuine PyPI project with
a genuine owner, so no existence check catches it and calling it malicious would be false.
TrustLayer scores it 35 — one edit from `beautifulsoup4` (25) plus a single maintainer
account (10) — which lands at LOW and reads `unfamiliar-dependency`. Not an accusation. A
flag that says: you are one character away from the package you meant.

It cannot reach MEDIUM on those two facts, by construction. Typo-adjacency is worth 25 and
MEDIUM starts at 40, so being near a popular name is never enough on its own to call
something suspicious. It takes youth or near-zero downloads on top.

Nothing here is installed, and nothing needs to be. The whole point is that this file is
dangerous *before* anyone runs `pip install`.
