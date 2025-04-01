package decode_diameter

import (
	database "DeepPacketAI/internal/storage"
	"fmt"
	"strconv"

	"github.com/blorticus-go/diameter"
)

func Process(p []byte, src_ipaddr string, dst_ipaddr string, time string, frame_num uint64) {
	diameter, err := diameter.DecodeMessage(p)
	if err != nil {
		return // Skip to the next packet if decoding fails
	}
	message := parseDiameterMessage(diameter)

	// Store processed message in database
	// Includes packet metadata and parsed content
	database.Insert(
		src_ipaddr, // Source IP address
		dst_ipaddr, // Destination IP address
		"diameter", // Protocol identifier
		time,       // Packet timestamp
		frame_num,  // Frame sequence number
		message,    // Parsed message content
	)
}

func parseDiameterMessage(diameterMessage *diameter.Message) map[string]string {
	parsedMessageMap := make(map[string]string)

	// Header Fields
	parsedMessageMap["Version"] = strconv.Itoa(int(diameterMessage.Version))
	parsedMessageMap["Length"] = strconv.Itoa(int(diameterMessage.Length))    // Uint24 - will be represented as int
	parsedMessageMap["Flags"] = fmt.Sprintf("0x%02x", diameterMessage.Flags)  // Hex representation of flags byte
	parsedMessageMap["CommandCode"] = strconv.Itoa(int(diameterMessage.Code)) // Uint24 - will be represented as int
	parsedMessageMap["ApplicationID"] = strconv.FormatUint(uint64(diameterMessage.AppID), 10)
	parsedMessageMap["HopByHopID"] = strconv.FormatUint(uint64(diameterMessage.HopByHopID), 10)
	parsedMessageMap["EndToEndID"] = strconv.FormatUint(uint64(diameterMessage.EndToEndID), 10)
	parsedMessageMap["RequestBit"] = strconv.FormatBool(diameterMessage.IsRequest())                                  // Using IsRequest() method
	parsedMessageMap["ProxiableBit"] = strconv.FormatBool(diameterMessage.IsProxiable())                              // Using IsProxiable() method
	parsedMessageMap["ErrorBit"] = strconv.FormatBool(diameterMessage.IsError())                                      // Using IsError() method
	parsedMessageMap["IsAnswer"] = strconv.FormatBool(diameterMessage.IsAnswer())                                     // Using IsTrunked() method
	parsedMessageMap["IsPotentiallyRetransmitted"] = strconv.FormatBool(diameterMessage.IsPotentiallyRetransmitted()) // Using IsTrunked() method

	// Extended Message Attributes (if present)
	if diameterMessage.ExtendedAttributes != nil {
		parsedMessageMap["MessageExtendedAttribute_Name"] = diameterMessage.ExtendedAttributes.Name
		parsedMessageMap["MessageExtendedAttribute_AbbreviatedName"] = diameterMessage.ExtendedAttributes.AbbreviatedName
	}

	// AVPs
	for i, currentAvp := range diameterMessage.Avps { // Correct field name: Avps
		avpPrefix := fmt.Sprintf("AVP_%d_", i+1)
		parsedMessageMap[avpPrefix+"Code"] = strconv.FormatUint(uint64(currentAvp.Code), 10)
		parsedMessageMap[avpPrefix+"VendorSpecific"] = strconv.FormatBool(currentAvp.VendorSpecific) // Correct field name
		parsedMessageMap[avpPrefix+"Mandatory"] = strconv.FormatBool(currentAvp.Mandatory)           // Correct field name
		parsedMessageMap[avpPrefix+"Protected"] = strconv.FormatBool(currentAvp.Protected)           // Correct field name

		if currentAvp.VendorSpecific { // Check VendorSpecific flag
			parsedMessageMap[avpPrefix+"VendorID"] = strconv.FormatUint(uint64(currentAvp.VendorID), 10) // Correct field name
		}

		parsedMessageMap[avpPrefix+"Length"] = strconv.Itoa(currentAvp.Length)             // Correct field name
		parsedMessageMap[avpPrefix+"PaddedLength"] = strconv.Itoa(currentAvp.PaddedLength) // Correct field name
		parsedMessageMap[avpPrefix+"Data"] = fmt.Sprintf("%X", currentAvp.Data)            // Hex representation of Data (byte slice)

		// AVP Extended Attributes (if present)
		if currentAvp.ExtendedAttributes != nil {
			parsedMessageMap[avpPrefix+"ExtendedAttribute_Name"] = currentAvp.ExtendedAttributes.Name
			parsedMessageMap[avpPrefix+"ExtendedAttribute_DataType"] = strconv.FormatUint(uint64(currentAvp.ExtendedAttributes.DataType), 10) // Get string representation of enum
			typedValue := currentAvp.ExtendedAttributes.TypedValue
			if typedValue != nil {
				parsedMessageMap[avpPrefix+"ExtendedAttribute_TypedValueType"] = fmt.Sprintf("%T", typedValue)
				parsedMessageMap[avpPrefix+"ExtendedAttribute_TypedValue"] = fmt.Sprintf("%v", typedValue) // String representation of TypedValue
			}
		}
	}

	return parsedMessageMap
}
