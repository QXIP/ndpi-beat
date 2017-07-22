<img src="https://user-images.githubusercontent.com/1423657/28491403-0613832e-6ef1-11e7-8a9f-0c54cf0022bd.png" width="150" />

# nDPI Beat

#### NodeJS + nDPI FFI Bindings + Elasticsearch Bulk Exporter
This experimental, unoptimized, proof-of-concept application implements a "Beat-like" Elasticsearch Bulk shipper, feeding on nDPI protocol detections from a live capture socket as source. Do NOT use for any purpose other than crashing a thread.

##### What is nDPI ?
[nDPI](https://github.com/ntop/nDPI) is an open source LGPLv3 library for deep-packet inspection. Based on OpenDPI it includes ntop extensions. We have tried to push them into the OpenDPI source tree but nobody answered emails so we have decided to create our own source tree

### Install & Run
```
npm install
npm run mkndpi
npm start
```

## Protocol Usage
![](http://i.imgur.com/2sToP5i.png)

## Protocol Relations
![](http://i.imgur.com/xET4d9H.png)

#### Example Doc
```
{
  "_index": "ndpi-2017.07.16",
  "_type": "ndpi",
  "_id": "AV1Mf5Wbqfm0n-9A-lsL",
  "_score": null,
  "_source": {
    "l7_protocol": "HTTP",
    "tsl_protocol": "tcp",
    "saddr": {
      "addr": "10.0.0.2"
    },
    "daddr": {
      "addr": "10.0.0.1"
    },
    "sport": 19200,
    "dport": 48630,
    "psize": 1402,
    "ts": "2017-07-16T17:43:35.579Z"
  }
}
```

##### (C) QXIP BV, http://qxip.net
