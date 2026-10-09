"""A griffe extension for the API reference (zensical.toml): documents functions that only a stub's
`@overload`s define.

A `.pyi` declares an overloaded function with its overloads alone, without the implementation a
`.py` file has. griffe records overloads when it reads them, and attaches them to the
implementation that follows; in a stub none follows, so the function (e.g. `SecretKey.decode`, in
`python/ryjwt/_ryjwt.pyi`) isn't a member, and mkdocstrings leaves it out. This makes it one: its
overloads are its signatures (the reference shows only those, `overloads_only`), and its docstring
is the first overload's that has one.
"""

from griffe import Class, Extension, Function


class StubOverloads(Extension):
    """Makes each function a class has only overloads of (as in a stub) a member of the class."""

    def on_class_members(self, *, cls: Class, **_kwargs: object) -> None:
        for name, overloads in list(cls.overloads.items()):
            if not overloads or name in cls.members:
                continue
            last = overloads[-1]
            function = Function(
                name,
                lineno=overloads[0].lineno,
                endlineno=last.endlineno,
                parameters=last.parameters,
                returns=last.returns,
                parent=cls,
                analysis="static",
            )
            function.docstring = next((o.docstring for o in overloads if o.docstring), None)
            if function.docstring is not None:
                function.docstring.parent = function
            function.overloads = overloads
            cls.set_member(name, function)
            del cls.overloads[name]
