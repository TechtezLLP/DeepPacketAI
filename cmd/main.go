// main.go
// DeepPacketAI: Advanced Network Protocol Analyzer with AI Integration
//
// This application serves as a comprehensive network protocol analyzer that combines
// packet analysis with AI-powered insights. It supports multiple protocols including:
// - HTTP/2: Full frame analysis (HEADERS, DATA, SETTINGS)
// - SIP: Session management and call flow analysis
// - SDP: Media session parameter inspection
//
// Core Features:
// 1. Multi-Protocol Support:
//    - HTTP/2 traffic analysis and pattern detection
//    - SIP signaling flow analysis and call tracking
//    - SDP media session parameter validation
//
// 2. Web Interface:
//    - Interactive GUI for pcap file uploads
//    - Real-time AI chat interface
//    - Visual protocol flow representation
//
// 3. AI Integration:
//    - Pattern recognition across multiple protocols
//    - Security threat detection
//    - Performance bottleneck identification
//
// Example Usage Scenarios:
// 1. VoIP Analysis:
//    Input: ./deeppacketai
//    Analysis:
//    - Tracks SIP call establishments
//    - Validates SDP parameters
//    - Identifies call quality issues
//    Output: Detailed call flow analysis with quality metrics
//
// 2. Web Application Security:
//    Input: ./deeppacketai
//    Analysis:
//    - Inspects HTTP/2 headers and payloads
//    - Detects potential security threats
//    - Analyzes traffic patterns
//    Output: Security insights and anomaly detection
//
// 3. Interactive Analysis via Web GUI:
//    - Upload pcap files through web interface
//    - Select specific protocols for analysis
//    - Real-time chat with AI for insights
//    - Export analysis reports
//
// Performance Features:
// - Concurrent protocol processing
// - Efficient memory management for large captures
// - Real-time analysis capabilities
// - Scalable web interface

package main

import (
	chatgpt_api "DeepPacketAI/internal/ai-client/chatgpt-client"
)

// main initializes and orchestrates the DeepPacketAI analysis pipeline
// Core workflow:
// 1. Web Interface Initialization:
//   - Sets up HTTP server for GUI
//   - Configures upload handlers
//   - Initializes AI chat interface
//
// 2. Protocol Analysis Pipeline:
//   - HTTP/2: Header compression, frame analysis
//   - SIP: Transaction tracking, dialog management
//   - SDP: Media parameter validation
//
// 3. AI Integration:
//   - Real-time pattern analysis
//   - Protocol-specific insights
//   - Interactive query handling
//
// Error Handling:
// - Invalid file uploads
// - Protocol parsing errors
// - AI service connectivity issues
//
// Usage Examples:
// 1. Web Interface:
//
//   - Access GUI at http://localhost:8080
//
//   - Upload pcap files through browser
//
//   - Interact with AI for analysis
//
//     2. Command Line:
//     ./deeppacketai
func main() {
	// Initialize web interface and AI chat functionality
	chatgpt_api.HandleWebPage()
}
