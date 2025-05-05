# OpenBubbles Build Modules

These modules can be used to build [OpenBubbles](https://github.com/OpenBubbles/openbubbles-app) from source with full
capabilities.

This is required if you want to make contributions to OpenBubbles, because the OpenBubbles project is not open
source. Some of its dependencies (particularly, the dependencies for generating Mac validation data) are closed
source.

While you can build OpenBubbles without these modules, you will not be able to sign in using Mac hardware information.

This project depends on a shared library
from [one of the x86_64 OpenBubbles release builds](https://github.com/OpenBubbles/openbubbles-app/releases/tag/v1.15.0%2B137).
It calls the functions OpenBubbles normally calls in a release build to generate the signed validation data.
