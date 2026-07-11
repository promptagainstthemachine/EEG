"""Clean fixture — no secrets, no LLM calls, no dangerous sinks."""


def greet(name: str) -> str:
    return f"hello {name.strip()}"


if __name__ == "__main__":
    print(greet("world"))
