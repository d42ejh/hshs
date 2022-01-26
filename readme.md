# hshs
Simple sha3-512 hashcash.(Some features may not available)  
Still work in progress but most of fundamental features are done.

# Usage
Please refer to [practical_example.rs](https://github.com/d42ejh/hshs/blob/master/examples/practical_example.rs)

## byte order
Default byte order is little endian.  
Please enable "bytes_be" feature flag to change to big endian.  

# Dependencies
a -> z 

bytecheck: <https://github.com/rkyv/bytecheck>  
chrono: <https://github.com/chronotope/chrono>  
openssl (rust binding): <https://github.com/sfackler/rust-openssl>  
rkyv: <https://github.com/rkyv/rkyv>  

# License
MIT