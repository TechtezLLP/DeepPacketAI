# DeepPacketAI

DeepPacketAI is a Go-based network traffic analyzer with AI integration. It decodes and processes live and stored packet captures, supporting LTE, 5G, SIP, RTP, HTTP, and more.

## Features
- Packet analysis for LTE/5G, GTP, SIP, RTP, and HTTP
- AI-driven anomaly detection using OpenAI, Gemini or Llama models
- Modular design for protocol extensions
- SQLite storage for traffic insights
- Command-line interface for batch processing

## Installation
To set the OpenAI and Gemini API keys

On Linux/macOS : 
export OPENAI_API_KEY="your-openai-key"
export GEMINI_API_KEY="your-gemini-key"
Then, apply the changes:
source ~/.bashrc  # or source ~/.zshrc

On Windows :
Command Prompt:
setx OPENAI_API_KEY "your-openai-key"
setx GEMINI_API_KEY "your-gemini-key"
PowerShell:
[System.Environment]::SetEnvironmentVariable("OPENAI_API_KEY", "your-openai-key", "User")
[System.Environment]::SetEnvironmentVariable("GEMINI_API_KEY", "your-gemini-key", "User")

Verifying the Variables:
echo $OPENAI_API_KEY   # On Linux/macOS
echo %OPENAI_API_KEY%  # On Windows CMD
$env:OPENAI_API_KEY    # On PowerShell


### Prerequisites
- Go 1.21+
- SQLite3
- Make (for Unix-based systems)


### Steps
```sh
git clone https://github.com/yourusername/DeepPacketAI.git
Go to extracted zip file path using command - cd /path/to/project
Open a Terminal or Command Prompt  
cd DeepPacketAI


### Running the Analyzer
To Install Dependencies run - go mod tidy
Run the Project using - go run ./cmd/main.go
TO build use - go build ./cmd/main.go
```

## Configuration
Edit `config.yaml` to adjust model parameters and analysis settings.

## Folder Structure 
DeepPacketAI/
├── cmd/
│   └── analyzer/
│       └── main.go
├── internal/
│   ├── analyzer/
│   │   └── processor.go
│   └── storage/
│       └── database.go
├── pkg/
│   └── ai/
│       └── analyzer.go
├── decode/
│   ├── decoder.go
│   ├── dns.go
│   ├── http.go
│   ├── rtcp.go
│   └── sip.go
├── config.yaml
├── go.mod
├── go.sum
├── Makefile
├── README.md
└── requirements.txt

## License
License is fully with TechTez-LLP
