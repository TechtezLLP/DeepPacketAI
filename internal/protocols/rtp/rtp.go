package decode_rtp

import (
	database "DeepPacketAI/internal/storage"
	"encoding/hex"
	"strconv"

	"github.com/google/gopacket"
	"github.com/sipcapture/heplify/ownlayers"
)

// Create a decoding layer parser and add your custom decoder
var parser *gopacket.DecodingLayerParser

func Process(l gopacket.Layer, src_ipaddr string, dst_ipaddr string, time string, frame_num uint64) {
	rtp, _ := l.(*ownlayers.RTP)
	message := parseRTPMessage(rtp)
	database.Insert(
		src_ipaddr, // Source IP address
		dst_ipaddr, // Destination IP address
		"rtp",      // Protocol identifier
		time,       // Packet timestamp
		frame_num,  // Frame sequence number
		message,    // Parsed message content
	)

}

// Function to convert RTP struct to map[string]string
func parseRTPMessage(rtp *ownlayers.RTP) map[string]string {
	rtpData := make(map[string]string)

	// Convert numerical values to strings
	rtpData["Version"] = strconv.Itoa(int(rtp.Version))
	rtpData["Padding"] = strconv.Itoa(int(rtp.Padding))
	rtpData["Extension"] = strconv.Itoa(int(rtp.Extension))
	rtpData["CC"] = strconv.Itoa(int(rtp.CC))
	rtpData["Marker"] = strconv.Itoa(int(rtp.Marker))
	rtpData["PayloadType"] = strconv.Itoa(int(rtp.PayloadType))
	rtpData["SequenceNumber"] = strconv.Itoa(int(rtp.SequenceNumber))
	rtpData["Timestamp"] = strconv.Itoa(int(rtp.Timestamp))
	rtpData["Ssrc"] = strconv.Itoa(int(rtp.Ssrc))

	// Convert CSRC (array) to string
	var csrcStr string
	for _, csrc := range rtp.Csrc {
		csrcStr += strconv.Itoa(int(csrc)) + " "
	}
	rtpData["Csrc"] = csrcStr

	// Convert Extension Headers
	rtpData["ExtensionHeaderID"] = strconv.Itoa(int(rtp.ExtensionHeaderID))
	rtpData["ExtensionHeaderLength"] = strconv.Itoa(int(rtp.ExtensionHeaderLength))
	rtpData["ExtensionHeader"] = hex.EncodeToString(rtp.ExtensionHeader)

	// Convert Payload and Contents to Hex format for readability
	rtpData["Payload"] = hex.EncodeToString(rtp.Payload)
	rtpData["Contents"] = hex.EncodeToString(rtp.Contents)

	return rtpData
}
