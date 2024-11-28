# arti-bin-shared

Common code for all Arti binaries.

## Overview

This crate is part of [Arti][arti],
a project to implement [Tor][tor] in Rust.

[arti]: https://gitlab.torproject.org/tpo/core/arti/
[tor]: https://www.torproject.org/

This library contains code that is shared between Arti binaries,
such as configuration loading, logging, cli structure, and more.

This library is *not* stable and there is no intention for it to become stable.
It is for internal use in Arti binary crates
(currently 'arti' and 'arti-relay').
If there is functionality that you'd also like to use in your own application,
let us know by [filing an issue][issue].

[issue]: https://gitlab.torproject.org/tpo/core/arti/-/issues
