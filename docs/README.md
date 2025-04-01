# DeepPacketAI

DeepPacketAI is a comprehensive network analysis tool that leverages multiple AI models (Gemini, ChatGPT, DeepSeek, Ollama) for advanced packet analysis, supporting HTTP/2 and SIP/SDP protocols for enhanced network monitoring and security analysis.

## Features

- **Multi-Protocol Support**: 
  - HTTP/2 traffic analysis with HPACK header processing
  - SIP/SDP analysis for VoIP traffic inspection
  - Real-time packet processing
  
- **AI-Powered Analysis**:
  - Google Gemini Pro for fast, accurate insights
  - OpenAI GPT-4 for detailed pattern analysis
  - DeepSeek for specialized network analysis
  - Ollama for local, privacy-focused processing

- **Interactive Interface**:
  - Web-based UI for real-time analysis
  - File upload support for pcap analysis
  - Chat interface for AI interactions
  - Cross-platform compatibility

## Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Use Cases](#use-cases)
- [Project Structure](#project-structure)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)

## Prerequisites

- Go 1.21 or higher
- API keys for chosen AI services:
  - Google Cloud API key (Gemini)
  - OpenAI API key (ChatGPT)
  - DeepSeek API key
  - Ollama local installation (optional)
- Platform-specific requirements:
  - **macOS**: Built-in libpcap
  - **Linux**: `libpcap-dev` package
  - **Windows**: [Npcap](https://npcap.com/)

## Installation

### macOS (Apple Silicon/Intel)
```bash
# Install dependencies
brew install go

# Clone repository
git clone https://github.com/yourusername/DeepPacketAI.git
cd DeepPacketAI

# Build for your architecture
make build-arm64    # For M1/M2 Macs
make build-amd64    # For Intel Macs
```

### Linux
```bash
# Install dependencies
sudo apt-get update && sudo apt-get install -y golang libpcap-dev

# Clone and build
git clone https://github.com/yourusername/DeepPacketAI.git
cd DeepPacketAI
make build-linux
```

### Windows
```powershell
# Install required software:
# 1. Go (from https://golang.org)
# 2. Npcap (from https://npcap.org)

# Clone and build
git clone https://github.com/yourusername/DeepPacketAI.git
cd DeepPacketAI
make build-windows
```

## Usage

### Command Line Options
```bash
Usage: deeppacketai [options]
  -i, --input string     Input pcap file path
  -p, --prompt string    Analysis prompt for AI
  --model string         AI model (gemini|chatgpt|deepseek|ollama)
  --url string          Custom API endpoint (for Ollama)
  --start string        Start time for analysis (HH:MM:SS)
  --end string          End time for analysis (HH:MM:SS)
```

### Examples

1. Basic Analysis with Gemini
```bash
./deeppacketai -i capture.pcap -p "Analyze SIP calls" --model gemini
```

2. Local Analysis with Ollama
```bash
./deeppacketai -i capture.pcap -p "Check for anomalies" --model ollama --url http://localhost:11434
```

## Use Cases

### 1. Security Analysis
- Detect potential security threats in HTTP/2 traffic
- Identify unusual traffic patterns and anomalies
- Monitor suspicious IP addresses and endpoints

### 2. Performance Monitoring
- Analyze response times and throughput patterns
- Identify network bottlenecks
- Track HTTP/2 stream performance

### 3. Debugging
- Inspect HTTP/2 headers and payloads
- Validate JSON content formatting
- Track request-response patterns

## Project Structure
```
DeepPacketAI/
├── bin/                    # Compiled binaries
├── cmd/                    # Application entry point
├── docs/                  # Documentation
├── internal/              # Private application code
│   ├── ai-client/        # AI model integrations
│   │   ├── chatgpt-client/   # OpenAI integration
│   ├── analyzer/         # Packet analysis logic
│   ├── protocols/        # Protocol implementations
│   │   ├── http/        # HTTP/2 processing
│   │   └── sip/         # SIP/SDP processing
│   └── storage/         # Data persistence
├── pkg/                   # Public library code
├── Makefile              # Build automation
└── go.mod                # Go module file
```

## Development

### Building from Source
```bash
make build          # Build all variants
make test           # Run test suite
make clean          # Clean build artifacts
```

### Adding New AI Models
1. Create new integration in `internal/ai-client/`
2. Implement the standard analysis interface
3. Add model selection in main configuration
4. Update web interface for new model

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This software is proprietary and confidential. Unauthorized copying, modification, distribution, or use of this software is strictly prohibited. See the LICENSE file for details.