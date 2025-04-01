package decode_rtcp

import (
	database "DeepPacketAI/internal/storage"
	"fmt"
	"strconv"
	"strings"

	"github.com/pion/rtcp"
)

func Process(p []byte, src_ipaddr string, dst_ipaddr string, time string, frame_num uint64) {
	rtcpPacket, err := rtcp.Unmarshal(p)
	if err != nil {
		return // Skip to the next packet if decoding fails
	}
	message := parseRTCPMessage(rtcpPacket)

	// Store processed message in database
	// Includes packet metadata and parsed content
	database.Insert(
		src_ipaddr, // Source IP address
		dst_ipaddr, // Destination IP address
		"rtcp",     // Protocol identifier
		time,       // Packet timestamp
		frame_num,  // Frame sequence number
		message,    // Parsed message content
	)
}

func parseRTCPMessage(rtcpPackets []rtcp.Packet) map[string]string {
	parsedMessageMap := make(map[string]string)

	for packetIndex, pkt := range rtcpPackets {
		messagePrefix := fmt.Sprintf("RTCPMessage_%d_", packetIndex+1) // Prefix for multiple messages

		switch rtcpPkt := pkt.(type) {
		case *rtcp.SenderReport:
			parsedMessageMap[messagePrefix+"MessageType"] = "SenderReport"
			parsedMessageMap[messagePrefix+"SSRC"] = strconv.FormatUint(uint64(rtcpPkt.SSRC), 10)
			parsedMessageMap[messagePrefix+"NTPTime"] = strconv.FormatUint(rtcpPkt.NTPTime, 10)
			parsedMessageMap[messagePrefix+"RTPTime"] = strconv.FormatUint(uint64(rtcpPkt.RTPTime), 10)
			parsedMessageMap[messagePrefix+"PacketCount"] = strconv.FormatUint(uint64(rtcpPkt.PacketCount), 10)
			parsedMessageMap[messagePrefix+"OctetCount"] = strconv.FormatUint(uint64(rtcpPkt.OctetCount), 10)
			for i, report := range rtcpPkt.Reports {
				reportPrefix := fmt.Sprintf("%sReport_%d_", messagePrefix, i+1)
				parsedMessageMap[reportPrefix+"SSRC"] = strconv.FormatUint(uint64(report.SSRC), 10)
				parsedMessageMap[reportPrefix+"FractionLost"] = strconv.FormatUint(uint64(report.FractionLost), 10)
				parsedMessageMap[reportPrefix+"TotalLost"] = strconv.FormatUint(uint64(report.TotalLost), 10)
				parsedMessageMap[reportPrefix+"LastSequenceNumber"] = strconv.FormatUint(uint64(report.LastSequenceNumber), 10)
				parsedMessageMap[reportPrefix+"Jitter"] = strconv.FormatUint(uint64(report.Jitter), 10)
				parsedMessageMap[reportPrefix+"LastSenderReport"] = strconv.FormatUint(uint64(report.LastSenderReport), 10)
				parsedMessageMap[reportPrefix+"Delay"] = strconv.FormatUint(uint64(report.Delay), 10)
			}
			parsedMessageMap[messagePrefix+"ProfileExtensions"] = fmt.Sprintf("%v", rtcpPkt.ProfileExtensions) // Byte slice as string

		case *rtcp.ReceiverReport:
			parsedMessageMap[messagePrefix+"MessageType"] = "ReceiverReport"
			parsedMessageMap[messagePrefix+"SSRC"] = strconv.FormatUint(uint64(rtcpPkt.SSRC), 10)
			for i, report := range rtcpPkt.Reports {
				reportPrefix := fmt.Sprintf("%sReport_%d_", messagePrefix, i+1)
				parsedMessageMap[reportPrefix+"SSRC"] = strconv.FormatUint(uint64(report.SSRC), 10)
				parsedMessageMap[reportPrefix+"FractionLost"] = strconv.FormatUint(uint64(report.FractionLost), 10)
				parsedMessageMap[reportPrefix+"TotalLost"] = strconv.FormatUint(uint64(report.TotalLost), 10)
				parsedMessageMap[reportPrefix+"LastSequenceNumber"] = strconv.FormatUint(uint64(report.LastSequenceNumber), 10)
				parsedMessageMap[reportPrefix+"Jitter"] = strconv.FormatUint(uint64(report.Jitter), 10)
				parsedMessageMap[reportPrefix+"LastSenderReport"] = strconv.FormatUint(uint64(report.LastSenderReport), 10)
				parsedMessageMap[reportPrefix+"Delay"] = strconv.FormatUint(uint64(report.Delay), 10)
			}
			parsedMessageMap[messagePrefix+"ProfileExtensions"] = fmt.Sprintf("%v", rtcpPkt.ProfileExtensions) // Byte slice as string

		case *rtcp.SourceDescription:
			parsedMessageMap[messagePrefix+"MessageType"] = "SourceDescription"
			for chunkIndex, chunk := range rtcpPkt.Chunks {
				chunkPrefix := fmt.Sprintf("%sChunk_%d_", messagePrefix, chunkIndex+1)
				parsedMessageMap[chunkPrefix+"Source"] = strconv.FormatUint(uint64(chunk.Source), 10)
				for itemIndex, item := range chunk.Items {
					itemPrefix := fmt.Sprintf("%sItem_%d_", chunkPrefix, itemIndex+1)
					parsedMessageMap[itemPrefix+"Type"] = item.Type.String()
					parsedMessageMap[itemPrefix+"Text"] = item.Text
				}
			}

		case *rtcp.Goodbye:
			parsedMessageMap[messagePrefix+"MessageType"] = "Goodbye"
			sourcesStr := ""
			for _, source := range rtcpPkt.Sources {
				sourcesStr += strconv.FormatUint(uint64(source), 10) + ", "
			}
			if len(sourcesStr) > 2 {
				sourcesStr = sourcesStr[:len(sourcesStr)-2] // Remove trailing ", "
			}
			parsedMessageMap[messagePrefix+"Sources"] = sourcesStr
			parsedMessageMap[messagePrefix+"Reason"] = rtcpPkt.Reason

		case *rtcp.ApplicationDefined:
			parsedMessageMap[messagePrefix+"MessageType"] = "ApplicationDefined"
			parsedMessageMap[messagePrefix+"SubType"] = strconv.FormatUint(uint64(rtcpPkt.SubType), 10)
			parsedMessageMap[messagePrefix+"SSRC"] = strconv.FormatUint(uint64(rtcpPkt.SSRC), 10)
			parsedMessageMap[messagePrefix+"Name"] = rtcpPkt.Name
			parsedMessageMap[messagePrefix+"Data"] = string(rtcpPkt.Data) // Byte slice as string

		case *rtcp.TransportLayerNack:
			parsedMessageMap[messagePrefix+"MessageType"] = "TransportLayerNack"
			parsedMessageMap[messagePrefix+"SenderSSRC"] = strconv.FormatUint(uint64(rtcpPkt.SenderSSRC), 10)
			parsedMessageMap[messagePrefix+"MediaSSRC"] = strconv.FormatUint(uint64(rtcpPkt.MediaSSRC), 10)
			nackPairsStr := ""
			for _, nackPair := range rtcpPkt.Nacks {
				nackPairsStr += fmt.Sprintf("{PacketID: %d, LostMask: %d}, ", nackPair.PacketID, nackPair.LostPackets)
			}
			if len(nackPairsStr) > 2 {
				nackPairsStr = nackPairsStr[:len(nackPairsStr)-2]
			}
			parsedMessageMap[messagePrefix+"NackPairs"] = nackPairsStr

		case *rtcp.PictureLossIndication:
			parsedMessageMap[messagePrefix+"MessageType"] = "PictureLossIndication"
			parsedMessageMap[messagePrefix+"SenderSSRC"] = strconv.FormatUint(uint64(rtcpPkt.SenderSSRC), 10)
			parsedMessageMap[messagePrefix+"MediaSSRC"] = strconv.FormatUint(uint64(rtcpPkt.MediaSSRC), 10)

		case *rtcp.CCFeedbackReport:
			parsedMessageMap[messagePrefix+"MessageType"] = "CCFeedbackReport"
			parsedMessageMap[messagePrefix+"SenderSSRC"] = strconv.FormatUint(uint64(rtcpPkt.SenderSSRC), 10)
			parsedMessageMap[messagePrefix+"ReportTimestamp"] = strconv.FormatUint(uint64(rtcpPkt.ReportTimestamp), 10)
			for blockIndex, block := range rtcpPkt.ReportBlocks {
				blockPrefix := fmt.Sprintf("%sReportBlock_%d_", messagePrefix, blockIndex+1)
				parsedMessageMap[blockPrefix+"MediaSSRC"] = strconv.FormatUint(uint64(block.MediaSSRC), 10)
				parsedMessageMap[blockPrefix+"BeginSequence"] = strconv.FormatUint(uint64(block.BeginSequence), 10)
				for metricIndex, metric := range block.MetricBlocks {
					metricPrefix := fmt.Sprintf("%sMetricBlock_%d_", blockPrefix, metricIndex+1)
					parsedMessageMap[metricPrefix+"Received"] = strconv.FormatBool(metric.Received)
					parsedMessageMap[metricPrefix+"ECN"] = strconv.FormatUint(uint64(metric.ECN), 10)
					parsedMessageMap[metricPrefix+"ArrivalTimeOffset"] = strconv.FormatUint(uint64(metric.ArrivalTimeOffset), 10)
				}
			}

		case *rtcp.ExtendedReport:
			parsedMessageMap[messagePrefix+"MessageType"] = "ExtendedReport"
			parsedMessageMap[messagePrefix+"SenderSSRC"] = strconv.FormatUint(uint64(rtcpPkt.SenderSSRC), 10)
			// Note: ReportBlocks in ExtendedReport are interfaces, need further type switching if you need to parse details of each block type.
			reportBlockTypes := []string{}
			for _, reportBlock := range rtcpPkt.Reports {
				reportBlockTypes = append(reportBlockTypes, fmt.Sprintf("%T", reportBlock))
			}
			parsedMessageMap[messagePrefix+"ReportBlockTypes"] = strings.Join(reportBlockTypes, ", ") // Store types as string

		case *rtcp.FullIntraRequest:
			parsedMessageMap[messagePrefix+"MessageType"] = "FullIntraRequest"
			parsedMessageMap[messagePrefix+"SenderSSRC"] = strconv.FormatUint(uint64(rtcpPkt.SenderSSRC), 10)
			parsedMessageMap[messagePrefix+"MediaSSRC"] = strconv.FormatUint(uint64(rtcpPkt.MediaSSRC), 10)
			firEntriesStr := ""
			for _, firEntry := range rtcpPkt.FIR {
				firEntriesStr += fmt.Sprintf("{SSRC: %d, SequenceNumber: %d}, ", firEntry.SSRC, firEntry.SequenceNumber)
			}
			if len(firEntriesStr) > 2 {
				firEntriesStr = firEntriesStr[:len(firEntriesStr)-2]
			}
			parsedMessageMap[messagePrefix+"FIREntries"] = firEntriesStr

		case *rtcp.RapidResynchronizationRequest: // Using the corrected struct name
			parsedMessageMap[messagePrefix+"MessageType"] = "RapidResynchronizationRequest"
			parsedMessageMap[messagePrefix+"SenderSSRC"] = strconv.FormatUint(uint64(rtcpPkt.SenderSSRC), 10)
			parsedMessageMap[messagePrefix+"MediaSSRC"] = strconv.FormatUint(uint64(rtcpPkt.MediaSSRC), 10)

		case *rtcp.ReceiverEstimatedMaximumBitrate:
			parsedMessageMap[messagePrefix+"MessageType"] = "ReceiverEstimatedMaximumBitrate"
			parsedMessageMap[messagePrefix+"SenderSSRC"] = strconv.FormatUint(uint64(rtcpPkt.SenderSSRC), 10)
			parsedMessageMap[messagePrefix+"Bitrate"] = strconv.FormatFloat(float64(rtcpPkt.Bitrate), 'G', 4, 32) // Format float32
			ssrcsStr := ""
			for _, ssrc := range rtcpPkt.SSRCs {
				ssrcsStr += strconv.FormatUint(uint64(ssrc), 10) + ", "
			}
			if len(ssrcsStr) > 2 {
				ssrcsStr = ssrcsStr[:len(ssrcsStr)-2]
			}
			parsedMessageMap[messagePrefix+"SSRCs"] = ssrcsStr

		case *rtcp.SliceLossIndication:
			parsedMessageMap[messagePrefix+"MessageType"] = "SliceLossIndication"
			parsedMessageMap[messagePrefix+"SenderSSRC"] = strconv.FormatUint(uint64(rtcpPkt.SenderSSRC), 10)
			parsedMessageMap[messagePrefix+"MediaSSRC"] = strconv.FormatUint(uint64(rtcpPkt.MediaSSRC), 10)
			sliEntriesStr := ""
			for _, sliEntry := range rtcpPkt.SLI {
				sliEntriesStr += fmt.Sprintf("{First: %d, Number: %d, Picture: %d}, ", sliEntry.First, sliEntry.Number, sliEntry.Picture)
			}
			if len(sliEntriesStr) > 2 {
				sliEntriesStr = sliEntriesStr[:len(sliEntriesStr)-2]
			}
			parsedMessageMap[messagePrefix+"SLIEntries"] = sliEntriesStr

		default:
			parsedMessageMap[messagePrefix+"MessageType"] = "Unknown"
			parsedMessageMap[messagePrefix+"Type"] = fmt.Sprintf("%T", rtcpPkt)
		}
	}
	return parsedMessageMap
}
