# Integration tests

Real-host tests are opt-in because they require configured SSH aliases. CI covers the protocol, pagination, configuration guards, and the standard-library Python agent. The acceptance environment should additionally replay connection reuse, reconnect, GPU, job survival, incremental sync, and cross-host transfer scenarios.

