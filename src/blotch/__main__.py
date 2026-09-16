"""Enable ``python -m blotch ...``.

Lets the CLI run without the ``blotch`` console script being on PATH - handy
on Windows, where pip's Scripts directory is often not on PATH.
"""

from .cli import main

if __name__ == "__main__":
    main()
