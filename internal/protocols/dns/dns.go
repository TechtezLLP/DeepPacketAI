package decode_dns

import (
	database "DeepPacketAI/internal/storage"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func Process(l gopacket.Layer, src_ipaddr string, dst_ipaddr string, time string, frame_num uint64) {
	dns, _ := l.(*layers.DNS)
	message := parseDNSMessage(dns)
	database.Insert(
		src_ipaddr, // Source IP address
		dst_ipaddr, // Destination IP address
		"dns",      // Protocol identifier
		time,       // Packet timestamp
		frame_num,  // Frame sequence number
		message,    // Parsed message content
	)
}

// Function to parse DNS message into map[string]string
func parseDNSMessage(dns *layers.DNS) map[string]string {
	dnsData := make(map[string]string)

	// Convert numerical values to strings
	dnsData["ID"] = strconv.Itoa(int(dns.ID))
	dnsData["QR"] = strconv.FormatBool(dns.QR)
	dnsData["Opcode"] = strconv.Itoa(int(dns.OpCode))
	dnsData["AA"] = strconv.FormatBool(dns.AA)
	dnsData["TC"] = strconv.FormatBool(dns.TC)
	dnsData["RD"] = strconv.FormatBool(dns.RD)
	dnsData["RA"] = strconv.FormatBool(dns.RA)
	dnsData["Z"] = strconv.Itoa(int(dns.Z))
	dnsData["ResponseCode"] = strconv.Itoa(int(dns.ResponseCode))
	dnsData["QuestionsCount"] = strconv.Itoa(int(dns.QDCount))
	dnsData["AnswerCount"] = strconv.Itoa(int(dns.ANCount))
	dnsData["AuthorityCount"] = strconv.Itoa(int(dns.NSCount))
	dnsData["AdditionalCount"] = strconv.Itoa(int(dns.ARCount))

	// Extract Queries
	var queries []string
	for _, question := range dns.Questions {
		queries = append(queries, fmt.Sprintf("%s (Type: %d, Class: %d)", string(question.Name), question.Type, question.Class))
	}
	dnsData["Queries"] = strings.Join(queries, "; ")

	// Extract Answers
	var answers []string
	for _, answer := range dns.Answers {
		answers = append(answers, fmt.Sprintf("%s (Type: %d, Class: %d, TTL: %d, Data: %s)",
			string(answer.Name), answer.Type, answer.Class, answer.TTL, string(answer.Data)))
	}
	dnsData["Answers"] = strings.Join(answers, "; ")

	// Extract Authority Records
	var authority []string
	for _, auth := range dns.Authorities {
		authority = append(authority, fmt.Sprintf("%s (Type: %d, Class: %d, TTL: %d, Data: %s)",
			string(auth.Name), auth.Type, auth.Class, auth.TTL, string(auth.Data)))
	}
	dnsData["Authorities"] = strings.Join(authority, "; ")

	// Extract Additional Records
	var additional []string
	for _, add := range dns.Additionals {
		additional = append(additional, fmt.Sprintf("%s (Type: %d, Class: %d, TTL: %d, Data: %s)",
			string(add.Name), add.Type, add.Class, add.TTL, string(add.Data)))
	}
	dnsData["Additionals"] = strings.Join(additional, "; ")

	return dnsData
}
