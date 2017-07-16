# nDPI Beat

#### NodeJS + nDPI FFI Bindings + Elasticsearch Bulk Exporter
This experimental, unoptimized, proof-of-concept application implements a "Beat-like" Elasticsearch Bulk shipper, feeding on nDPI protocol detections from a live capture socket as source. Do NOT use for any purpose other than crashing a thread.

##### What is nDPI ?
[nDPI](https://github.com/ntop/nDPI) is an open source LGPLv3 library for deep-packet inspection. Based on OpenDPI it includes ntop extensions. We have tried to push them into the OpenDPI source tree but nobody answered emails so we have decided to create our own source tree

## Protocol Usage
![](http://i.imgur.com/2sToP5i.png)

## Protocol Relations
![](http://i.imgur.com/xET4d9H.png)

##### (C) QXIP BV, http://qxip.net
