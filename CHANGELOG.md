### 0.3.3 (2022-01-17)

#### Features
* zettabgp 0.3.3 with log crate and improvements for BMP

### 0.3.2 (2022-01-17)

#### Fixes
* timestamps in json fixed as ints

### 0.3.1 (2022-01-17)

#### Features
* websocket subscription for route changes
* Warnings on config peers load errors

#### Fixes
* BMP decode route monitoring with parameters from previously caught BGP OPEN messages
* Support for addpath detection for BMP route monitoring
* Dependencies versions advanced

### 0.3.0 (2021-10-10)

* multicast distribution tree safi support
* store BGP database into file on stop and load it on startup, config options:
   snapshot_file - file name
   snapshot_every - time interval to regular save

### 0.2.1 (2021-08-01)

* frontent tables replaced to css grid
* Multiple addpath 

### 0.1.3 (2021-07-20)

* multiple BGP sessions support

### 0.1.2 (2021-07-14)

* regular database cleanup
* configurable cache liftetime
* added parameters for whois cache and regular purge

### 0.1.1 (2021-05-23)

* frontend 120 sec api query timeout
* Indexing by aspath, communities and extended communities
* Config params was added:
 history mode
 http data lock timeout


### 0.1.0 (2021-05-04)

Release


