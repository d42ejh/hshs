# hshs
Simple sha3-512 [hashcash](https://en.wikipedia.org/wiki/Hashcash).  
[paper](https://link.springer.com/content/pdf/10.1007%2F3-540-48071-4_10.pdf)  

### done
I don't think I will be updating this project any further as it has already fulfilled the requirements from my other projects.  

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


