// Package decode implements comprehensive network packet analysis
// Supports multiple protocols and both live and offline analysis
package decode

// Required imports for packet processing and protocol analysis
import (
	decode_diameter "DeepPacketAI/internal/protocols/diameter"
	decode_dns "DeepPacketAI/internal/protocols/dns"
	decode_http "DeepPacketAI/internal/protocols/http" // HTTP/2 protocol decoder
	decode_rtcp "DeepPacketAI/internal/protocols/rtcp"
	decode_rtp "DeepPacketAI/internal/protocols/rtp"
	decode_sip "DeepPacketAI/internal/protocols/sip" // SIP protocol decoder
	"DeepPacketAI/pkg/config"                        // Application configuration
	"fmt"                                            // Formatted I/O operations
	"time"                                           // Time-related functions

	"github.com/google/gopacket"        // Core packet processing
	"github.com/google/gopacket/layers" // Protocol layer definitions
	"github.com/google/gopacket/pcap"   // Packet capture functionality
	"github.com/sipcapture/heplify/ownlayers"
)

// processPcapFile handles the analysis of a single pcap file
// Parameters:
//   - file: Path to the pcap file for analysis
func processPcapFile(file string) {
	// Open pcap file for reading
	// Returns handle for packet operations
	h, err := pcap.OpenOffline(file)
	if err != nil {
		fmt.Println("Error opening", file, "file", "err:", err)
		return
	}
	// Ensure file handle is closed after processing
	defer h.Close()

	// Get total packet count for progress tracking
	// Enables accurate progress percentage calculation
	total_packets := totalPackets()

	// Initialize packet counter for sequential processing
	// Used for maintaining packet order in analysis
	var frame uint64

	// Create packet source from pcap handle
	// Uses appropriate link layer type for decoding
	p := gopacket.NewPacketSource(h, h.LinkType())

	// Process each packet in capture file
	// Handles packet extraction and protocol analysis
	for packet := range p.Packets() {
		// Increment frame counter for progress tracking
		frame++

		// Calculate and display processing progress
		// Shows percentage of packets processed
		progress := float64(frame) / float64(total_packets) * 100
		fmt.Printf("\rProgress: %.2f%%", progress)

		// Extract IP layer information
		// Contains source and destination addresses
		network := packet.NetworkLayer()
		if network == nil {
			continue // Skip packets without network layer
		}

		// Validate IP addresses
		// Skip packets with invalid addresses (0.0.0.0)
		if network.NetworkFlow().Dst().String() == "0.0.0.0" &&
			network.NetworkFlow().Src().String() == "0.0.0.0" {
			continue
		}

		// Check for SIP protocol packets
		// Process VoIP signaling if present
		sip := packet.Layer(layers.LayerTypeSIP)
		if sip != nil {
			// Process SIP packet with metadata
			decode_sip.Process(
				sip,                                  // SIP layer data
				network.NetworkFlow().Src().String(), // Source IP
				network.NetworkFlow().Dst().String(), // Destination IP
				packet.Metadata().Timestamp.Format(time.RFC3339), // Timestamp
				frame, // Packet number
			)
			continue
		}

		// Check for RTP protocol packets
		rtp := packet.Layer(ownlayers.LayerTypeRTP)
		if rtp != nil {
			// Process RTP packet with metadata
			decode_rtp.Process(
				rtp,                                  // RTP layer data
				network.NetworkFlow().Src().String(), // Source IP
				network.NetworkFlow().Dst().String(), // Destination IP
				packet.Metadata().Timestamp.Format(time.RFC3339), // Timestamp
				frame, // Packet number
			)
			continue
		}

		// Check for DNS protocol packets
		dns := packet.Layer(layers.LayerTypeDNS)
		if dns != nil {
			// Process RTP packet with metadata
			decode_dns.Process(
				dns,                                  // DNS layer data
				network.NetworkFlow().Src().String(), // Source IP
				network.NetworkFlow().Dst().String(), // Destination IP
				packet.Metadata().Timestamp.Format(time.RFC3339), // Timestamp
				frame, // Packet number
			)
			continue
		}

		// Check for UDP protocol packets
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer != nil {
			// udp, _ := udpLayer.(*layers.UDP)
			// You might want to filter based on port numbers here if you know them
			// Example: if udp.DstPort == 5005 || udp.DstPort == 5006 { // Example RTCP ports

			// 3. Extract UDP payload and attempt to decode as RTCP
			app := packet.ApplicationLayer()
			if app != nil {
				rtcpPayload := app.Payload()
				// Decode Diameter packet
				decode_rtcp.Process(
					rtcpPayload,                                      // HTTP/2 frame data
					network.NetworkFlow().Src().String(),             // Source IP
					network.NetworkFlow().Dst().String(),             // Destination IP
					packet.Metadata().Timestamp.Format(time.RFC3339), // Timestamp
					frame, // Packet number
				)
			}
			continue
		}

		// Extract STCP layer for transport protocol
		// Required for Diameter analysis
		stcp := packet.Layer(layers.LayerTypeSCTP)
		if stcp != nil {
			sctpPkt := stcp.(*layers.SCTP)
			if sctpPkt.DstPort == 3868 || sctpPkt.SrcPort == 3868 || sctpPkt.DstPort == 1677 || sctpPkt.SrcPort == 1677 {
				app := packet.ApplicationLayer()
				if app != nil {
					diameterPayload := app.Payload()
					// Decode Diameter packet
					decode_diameter.Process(
						diameterPayload,                                  // HTTP/2 frame data
						network.NetworkFlow().Src().String(),             // Source IP
						network.NetworkFlow().Dst().String(),             // Destination IP
						packet.Metadata().Timestamp.Format(time.RFC3339), // Timestamp
						frame, // Packet number
					)
				}
			}
			continue // Skip non-SCTP packets
		}

		// Extract TCP layer for transport protocol
		// Required for Diameter analysis
		tcp := packet.Layer(layers.LayerTypeTCP)
		if tcp != nil {
			tcpPkt := tcp.(*layers.TCP)
			if tcpPkt.DstPort == 3868 || tcpPkt.SrcPort == 3868 {
				app := packet.ApplicationLayer()
				if app != nil {
					diameterPayload := app.Payload()
					// Decode Diameter packet
					decode_diameter.Process(
						diameterPayload,                                  // HTTP/2 frame data
						network.NetworkFlow().Src().String(),             // Source IP
						network.NetworkFlow().Dst().String(),             // Destination IP
						packet.Metadata().Timestamp.Format(time.RFC3339), // Timestamp
						frame, // Packet number
					)
				}
			}
			continue // Skip non-TCP packets
		}

		// Process application layer data
		// Contains protocol-specific content
		app := packet.ApplicationLayer()
		if app != nil {
			data := app.Payload()
			// Check for non-empty payload
			if len(data) > 0 {
				// Process HTTP/2 data with metadata
				decode_http.Process(
					data,                                 // HTTP/2 frame data
					network.NetworkFlow().Src().String(), // Source IP
					network.NetworkFlow().Dst().String(), // Destination IP
					packet.Metadata().Timestamp.Format(time.RFC3339), // Timestamp
					frame, // Packet number
				)
			}
			continue
		}
	}
	fmt.Println() // New line after progress display
}

// Process initializes and manages the packet analysis workflow
// Handles file reading and packet processing coordination
func Process() {
	// Process each configured pcap file
	// Supports batch analysis of multiple captures
	for _, file := range config.Input.Files {
		processPcapFile(file) // Process individual file
	}
}

// totalPackets counts packets in all configured pcap files
// Used for accurate progress tracking during analysis
func totalPackets() uint64 {
	// Initialize packet counter
	var count uint64 = 0

	// Process each configured file
	for _, file := range config.Input.Files {
		// Open pcap file for counting
		h, err := pcap.OpenOffline(file)
		if err != nil {
			fmt.Println("Error opening", file, "file", "err:", err)
			return 0
		}
		defer h.Close() // Ensure file handle is closed

		// Count packets in current file
		p := gopacket.NewPacketSource(h, h.LinkType())
		for range p.Packets() {
			count++ // Increment for each packet
		}
	}

	return count // Return total packet count
}

// Check if a packet is a Diameter packet
func isDiameterPacket(data []byte) bool {
	return len(data) > 20 && data[0] == 1 // Diameter Version = 1
}
