"use strict"

/*  nDPI Node.js Binding PoC 	*/
/*  (c) 2015-2017 QXIP BV 	*/
/*  http://qxip.net 		*/

var VERSION = "0.1.2";

var config = require('./config');
if (!config) quit('Missing Config!');

/* NODE REQs */
var ref = require('ref');
var ffi = require('ffi');
var Struct = require('ref-struct');
var ArrayType = require('ref-array');
var fs = require('fs');
var debug = config.debug;
var quit = function(){ console.log(e); process.exit(0); }
var pcap = require("pcap"),
    pcap_session = pcap.createSession(config.pcap.interface ? config.pcap.interface : "", 
				      config.pcap.filter ? config.pcap.filter : "" );
var elasticsearch = require('elasticsearch');
var client = new elasticsearch.Client(config.elastic.queue.options.client);
if (!client) { quit('Error generating ES client!');}

var ElasticStream = require('elasticsearch-writable-stream');
var queue = new ElasticStream(client, {
  highWaterMark: 256,
  flushTimeout: 500
});
if (!queue) { quit('Error generating ES stream!');}

queue
  .on('error', function(error) {
    // Handle error
	console.log(error);
  })
  .on('finish', function() {
    // Clean up Elasticsearch client?
	client.close();
  })

var IPv4 = require('pcap/decode/ipv4');
var TCP = require('pcap/decode/tcp');
var UDP = require('pcap/decode/udp');
var runner = {};

/* NDPI CALLBACK */

// On Windows UTF-16 (2-bytes), Unix UTF-32 (4-bytes)
runner.wchar_size = process.platform == 'win32' ? 2 : 4

runner.wchar_t = Object.create(ref.types.CString);
runner.wchar_t.get = function get (buf, offset) {
  var _buf = buf.readPointer(offset)
  if (_buf.isNull()) {
    return;
  }
  var stringBuf = _buf.reinterpretUntilZeros(runner.wchar_size)
  return stringBuf.toString('win32' ? 'utf16le' : 'utf32li') // TODO: decode UTF-32 on Unix
};

runner.wchar_t.set = function set (buf, offset, val) {
  // TODO: better UTF-16 and UTF-32 encoding
  var _buf = new Buffer((val.length + 1) * runner.wchar_size)
  _buf.fill(0)
  var l = 0
  for (var i = runner.wchar_size - 1; i < _buf.length; i += runner.wchar_size) {
    _buf[i] = val.charCodeAt(l++)
  }
  return buf.writePointer(_buf, offset)
};

runner.callback_Ptr = ArrayType(runner.wchar_t);

/* APP VARS */
runner.voidPtr = exports.voidPtr = ref.refType(ref.types.void);
runner.uint8_t = exports.uint8_t = runner.voidPtr;
runner.uint8_tPtr = exports.uint8_tPtr = ref.refType(runner.uint8_t);
runner.callback = exports.callback = ffi.Function(ref.types.void, [
  ref.types.int32,
  ref.refType(ref.types.uchar)
]);
runner.pcap_t = exports.pcap_t = runner.voidPtr;
runner.pcap_tPtr = exports.pcap_tPtr = ref.refType(runner.pcap_t);
runner.pcap_handler = exports.pcap_handler = ffi.Function(ref.types.void, [
  ref.refType(ref.types.uchar),
  runner.voidPtr,
  ref.refType(ref.types.uchar)
]);
runner.pcap_handlerPtr = exports.pcap_handlerPtr = ref.refType(runner.pcap_handler);

// PCAP Header
var pcap_pkthdr = Struct({
  'ts_sec': 'long',
  'ts_usec': 'long',
  'incl_len': 'int',
  'orig_len': 'int'
});

var pktHdr = new pcap_pkthdr;
pktHdr = ref.refType(ref.types.void);

runner.gcallback = ffi.Callback('void', [ref.types.int32, ref.refType(ref.types.uchar)],
  function(id) {
    if (debug) console.log("id: ", id);
  });

runner.ndpi = exports.ndpi = new ffi.Library('./lib/ndpiexlib.so', {
  init: [ref.types.void, [
  ]],
  setDatalinkType: [ref.types.void, [
      runner.pcap_tPtr,
  ]],
  processPacket: [ref.types.void, [
    runner.voidPtr,
    runner.uint8_t,
  ]],
  finish: [ref.types.void, [
  ]],
  addProtocolHandler: [ref.types.void, [
    runner.callback
  ]],
});


var L7PROTO = [
	"Unknown","FTP_CONTROL","POP3","SMTP","IMAP","DNS","IPP","HTTP","MDNS","NTP","NetBIOS","NFS","SSDP","BGP","SNMP","XDMCP","SMB","Syslog","DHCP","PostgreSQL","MySQL","TDS","Direct_Download_Link","POPS","AppleJuice","DirectConnect","Socrates","WinMX","VMware","SMTPS","Filetopia","iMESH","Kontiki","OpenFT","FastTrack","Gnutella","eDonkey","BitTorrent","EPP","AVI","Flash","OggVorbis","MPEG","QuickTime","RealMedia","WindowsMedia","MMS","Xbox","QQ","Move","RTSP","IMAPS","IceCast","PPLive","PPStream","Zattoo","ShoutCast","Sopcast","Tvants","TVUplayer","HTTP_APPLICATION_VEOHTV","QQLive","Thunder","Soulseek","SSL_No_Cert","IRC","Ayiya","Unencryped_Jabber","MSN","Oscar","Yahoo","BattleField","Quake","VRRP","Steam","HalfLife2","WorldOfWarcraft","Telnet","STUN","IPsec","GRE","ICMP","IGMP","EGP","SCTP","OSPF","IP_in_IP","RTP","RDP","VNC","PcAnywhere","SSL","SSH","Usenet","MGCP","IAX","TFTP","AFP","Stealthnet","Aimini","SIP","TruPhone","ICMPV6","DHCPV6","Armagetron","Crossfire","Dofus","Fiesta","Florensia","Guildwars","HTTP_Application_ActiveSync","Kerberos","LDAP","MapleStory","MsSQL","PPTP","Warcraft3","WorldOfKungFu","Meebo","Facebook","Twitter","DropBox","GMail","GoogleMaps","YouTube","Skype","Google","DCE_RPC","NetFlow","sFlow","HTTP_Connect","HTTP_Proxy","Citrix","NetFlix","LastFM","GrooveShark","SkyFile_PrePaid","SkyFile_Rudics","SkyFile_PostPaid","Citrix_Online","Apple","Webex","WhatsApp","AppleiCloud","Viber","AppleiTunes","Radius","WindowsUpdate","TeamViewer","Tuenti","LotusNotes","SAP","GTP","UPnP","LLMNR","RemoteScan","Spotify","WebM","H323","OpenVPN","NOE","CiscoVPN","TeamSpeak","TOR","CiscoSkinny","RTCP","RSYNC","Oracle","Corba","UbuntuONE","Whois-DAS","Collectd","SOCKS5","SOCKS4","RTMP","FTP_DATA","Wikipedia","ZeroMQ","Amazon","eBay","CNN","Megaco","Redis","Pando_Media_Booster","VHUA","Telegram","FacebookChat","Pandora","Vevo"
]

/* APP */

console.log("nDPI Node v"+VERSION);

var counter = 0, errors = 0;
var init = runner.ndpi.init();

var reboot = function(){
	runner.ndpi.finish();
	runner.ndpi.init();
}

/* PCAP LOOP */

console.log("Listening on " + pcap_session.device_name);

runner.onProto = function(id, packet) {
	if (id > 0 && debug) console.log("Proto: "+id+" "+L7PROTO[id]);
}

runner.getFlowInfo = function(packet,l7_protocol){
	if(packet.payload.payload instanceof IPv4){
		var ip = packet.payload.payload;
		var saddr = Array.prototype.join.call(ip.saddr, '.'); // ip.saddr;
		var daddr = Array.prototype.join.call(ip.daddr, '.'); // ip.daddr;
		var sport = tsl_packet.sport;
	    	var dport = tsl_packet.dport;
		var psize = packet.payload.payload.length;
		var tsl_packet = packet.payload.payload.payload;
		var tsl_protocol = '';
		if(tsl_packet instanceof TCP){
			tsl_protocol = 'tcp';
		}else if (tsl_packet instanceof UDP){
			tsl_protocol = 'udp';
		}else{
			tsl_protocol = 'unknown';
			if (debug) console.log('skip!');
		}
		return {l7_protocol,tsl_protocol,saddr,daddr,sport,dport,psize};
	}
}


runner.onPacketAnalyzedCallback = function(flow_info){
 try {
  if (debug) console.log( flow_info.psize+" bytes from "+flow_info.saddr+":"+flow_info.sport+" to "+flow_info.daddr+":"+flow_info.dport+" with protocol : "+flow_info.l7_protocol);
  var now = new Date();
  flow_info.ts = now.toISOString();
  var doc = {
	  index: config.elastic.queue.index+'-'+new Date(Date.UTC(now.getFullYear(), now.getMonth(), now.getDate())).toISOString().slice(0, 10).replace(/-/g, '.'),
	  type: 'ndpi',
	  action: 'index',
	  body: flow_info
  }
  queue.write(doc, function(e){ if(e) console.log(e); });
 } catch(e) { console.log(e); }

}

runner.ndpi.addProtocolHandler(runner.onProto);
runner.ndpiPipe = function(header,packet,callback){
	try {
		runner.ndpi.addProtocolHandler(function(id,p){
			if(id > 0){
				callback(runner.getFlowInfo(pcap.decode.packet(packet),L7PROTO[id]));
			}
		});
		runner.ndpi.processPacket(header, packet.buf);
	} catch(e) {
		errors++
	}
}

pcap_session.on('packet', function (raw_packet) {
        if (raw_packet.header) {
            counter++;
            runner.ndpiPipe(raw_packet.header.ref(), raw_packet, runner.onPacketAnalyzedCallback );
	    if (counter % 200 === 0 ) { reboot(); }
        }
});



var exit = false;

process.on('exit', function() {
    console.log('Exiting...');
    runner;
});

process.on('SIGINT', function() {
    console.log();
    if (exit) {
    	console.log("Exiting...");
	runner.ndpi.finish();
        process.exit();
    } else {
	console.log('Total Packets: '+counter, 'Total Errors: '+errors);
    	console.log("Press CTRL-C within 2 seconds to Exit...");
        exit = true;
	setTimeout(function () {
	  exit = false;
	}, 2000)
    }
});


