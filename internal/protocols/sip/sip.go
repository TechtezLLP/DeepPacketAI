// Package decode_sip implements SIP (Session Initiation Protocol) analysis
// Handles SIP signaling and associated SDP (Session Description Protocol) data
package decode_sip

// Required imports for SIP protocol analysis
import (
	database "DeepPacketAI/internal/storage" // Data persistence layer
	"strings"                                // String manipulation utilities

	"github.com/google/gopacket" // Packet capture and analysis
	"github.com/jart/gosip/sdp"  // SDP protocol parser
	"github.com/jart/gosip/sip"  // SIP protocol parser
)

// Process analyzes a SIP packet and extracts relevant information
// Parameters:
//   - l: Layer containing SIP packet data
//   - src_ipaddr: Source IP address
//   - dst_ipaddr: Destination IP address
//   - time: Packet capture timestamp
//   - frame_num: Sequential frame number
func Process(l gopacket.Layer, src_ipaddr string, dst_ipaddr string, time string, frame_num uint64) {

	// Parse SIP message header from packet contents
	// Combines header contents and payload for complete message
	msgHeader, _ := sip.ParseMsg(append(l.LayerContents(), l.LayerPayload()...))

	// Parse SDP body if present
	// Contains media session information
	msgBody, _ := sdp.Parse(string(l.LayerPayload()))

	// Process SIP headers into structured format
	// Extracts individual header fields and values
	message := parseSIPMessage(msgHeader.String())

	// Add parsed SDP body to message structure
	// Includes codec, media, and network information
	message["Message Body"] = msgBody.String()

	// Store processed message in database
	// Includes packet metadata and parsed content
	database.Insert(
		src_ipaddr, // Source IP address
		dst_ipaddr, // Destination IP address
		"sip",      // Protocol identifier
		time,       // Packet timestamp
		frame_num,  // Frame sequence number
		message,    // Parsed message content
	)
}

// parseSIPMessage extracts header fields from SIP message
// Parameters:
//   - sipHeader: Raw SIP header string
//
// Returns:
//   - Map of header field names to values
func parseSIPMessage(sipHeader string) map[string]string {
	// Split header into individual lines
	// Each line contains a header field
	lines := strings.Split(sipHeader, "\n")

	// Initialize map for storing header fields
	// Key: header name, Value: header content
	sipData := make(map[string]string)

	// Store first line as status/request line
	// Contains method, URI, and protocol version
	sipData["Status"] = strings.TrimSpace(lines[0])

	// Process remaining header lines
	for _, line := range lines[1:] {
		// Remove leading/trailing whitespace
		line = strings.TrimSpace(line)

		// Skip empty lines
		if line == "" {
			continue
		}

		// Split line into header name and value
		// Uses first colon as separator
		parts := strings.SplitN(line, ":", 2)

		// Store valid header fields in map
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])   // Header field name
			value := strings.TrimSpace(parts[1]) // Header field value
			sipData[key] = value
		}
	}

	return sipData // Return processed headers
}
