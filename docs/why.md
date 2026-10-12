# Why ryjwt

The vision and design of ryjwt are the author's, but AI has been used for nearly 100% of the
implementation, both code and docs (except for this page). It's driven by two pillars of modern
Python:

1. Python's modern type system, especially around generics (for example:
   `def decode[T](token: str, *, into: type[T]) -> T`), allows us to build elegant, generic and
   still strictly typed libraries in Python.
2. PyO3 and maturin have changed the game. Writing Python libraries in Rust is now (especially
   with AI) relatively easy, so we get the speed and safety of Rust with the high-level
   abstractions and beauty of a Python interface (for example: pyreqwest, Polars, Daft).
