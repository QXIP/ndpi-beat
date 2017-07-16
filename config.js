/* nDPI Beat Configuration */

module.exports = {
  debug: true,
  elastic: {
    queue: {
	index: "ndpi",
	options: {
	  interval: "day",
	  doctype: "ndpi",
	  indexSettings: { "number_of_shards" : 1 },
          client: {
		host: "http://127.0.0.1:9200",
		httpAuth: "admin:password"
	  }
	}
    }
  }
}
