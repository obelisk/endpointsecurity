# EndpointSecurity in Rust

This is a crate I wrote to power building EndpointSecurity products in Rust. This is still very much in active development and subject to significant changes (though the existing pub api I would expect to stay more or less the same).

EsClient is marked Send and Sync because to the best of my knowledge, it is. There are locks around using it inside the API because I don't know if EndpointSecurity is threadsafe. Your mileage may vary.

Not all calls are implemented, only the ones I've needed so far and some of the ones that are implemented are incomplete (most of the important stuff is there though).

Licenced under MIT because free software is important.
