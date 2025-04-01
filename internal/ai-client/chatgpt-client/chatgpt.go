// chatgpt.go implements comprehensive network protocol analysis with AI integration
// Core capabilities:
// - Multi-protocol analysis (HTTP/2, SIP, SDP)
// - Real-time traffic monitoring and pattern detection
// - AI-powered insight generation using GPT-4
// - Interactive web interface for file uploads and analysis
// - Cross-protocol correlation and anomaly detection

// Package chatgpt_api provides the core AI analysis functionality
// Handles communication with OpenAI API and maintains chat context
package chatgpt_api

import (
	decode "DeepPacketAI/internal/analyzer"  // Protocol decoder functionality
	database "DeepPacketAI/internal/storage" // Data persistence layer
	"DeepPacketAI/pkg/config"                // Application configuration
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"DeepPacketAI/internal/ai-client/generativeai" // Custom Gemini client

	"github.com/google/generative-ai-go/genai"
	"github.com/ollama/ollama/api"
	"github.com/sashabaranov/go-openai" // ChatGPT
	"google.golang.org/api/option"
)

var messages []openai.ChatCompletionMessage
var ollamaMessages []api.Message
var client *openai.Client
var ollamaClient *api.Client
var geminiClient *generativeai.Client
var ctx context.Context
var gemini_client *genai.Client
var cs *genai.ChatSession

// AIProvider represents the selected AI provider and model
type AIProvider struct {
	LLM   string `json:"llm"`
	Model string `json:"model"`
}

var currentAIProvider AIProvider

// prettyString formats JSON data with indentation
func prettyString(str string) (string, error) {
	var prettyJSON bytes.Buffer
	if err := json.Indent(&prettyJSON, []byte(str), "", "    "); err != nil {
		return "", err
	}
	return prettyJSON.String(), nil
}

// Chatgpt_ai_process initializes the AI analysis pipeline based on the selected provider
func Chatgpt_ai_process() error {
	fmt.Println("currentAIProvider.LLM:", currentAIProvider.LLM)

	jsonData, err := json.Marshal(database.AI_Input)
	if err != nil {
		return fmt.Errorf("Error marshalling data: %v", err)
	}

	res, err := prettyString(string(jsonData))
	if err != nil {
		return fmt.Errorf("Error formatting JSON: %v", err)
	}

	prompt := fmt.Sprintf("For the below data:\n%s\nAnswer the queries asked below.", string(res))

	switch currentAIProvider.LLM {
	case "ChatGPT":
		// Fetch ChatGPT API key from environment variable
		chatGPTAPIKey := os.Getenv("CHATGPT_API_KEY")
		if chatGPTAPIKey == "" {
			return fmt.Errorf("CHATGPT_API_KEY environment variable is not set")
		}
		client = openai.NewClient(chatGPTAPIKey)
	case "Ollama":
		url, _ := url.Parse("http://localhost:11434")
		ollamaClient = api.NewClient(url, http.DefaultClient) // Default Ollama API endpoint
		fmt.Println("Initializing Ollama with model:", currentAIProvider.Model)
	case "Gemini":
		// Fetch Gemini API key from environment variable
		// geminiAPIKey := os.Getenv("GEMINI_API_KEY")
		// if geminiAPIKey == "" {
		// 	fmt.Println("GEMINI_API_KEY environment variable is not set")
		// 	return fmt.Errorf("GEMINI_API_KEY environment variable is not set")
		// }
		// geminiClient = generativeai.NewClient(geminiAPIKey)
		// fmt.Println("Initializing Gemini with model:", currentAIProvider.Model)
		// Setup Gemini AI client with authentication from env
		// Initialize context for API request lifecycle
		ctx = context.Background()
		geminiAPIKey := os.Getenv("GEMINI_API_KEY")
		fmt.Println("geminiAPIKey:", geminiAPIKey)
		gemini_client, _ := genai.NewClient(ctx, option.WithAPIKey(geminiAPIKey))
		// Configure AI model for network traffic analysis
		// Model: gemini-1.5-flash optimized for pattern recognition
		model := gemini_client.GenerativeModel("gemini-1.5-flash")
		// Initialize the chat
		cs = model.StartChat()
		cs.History = []*genai.Content{
			{
				Parts: []genai.Part{
					genai.Text(prompt),
				},
				Role: "user",
			},
			{
				Parts: []genai.Part{
					genai.Text("Great to meet you. What would you like to know?"),
				},
				Role: "model",
			},
		}

	default:
		log.Fatal("Unsupported LLM selected")
	}

	if currentAIProvider.LLM == "Gemini" {

	} else if currentAIProvider.LLM == "Ollama" {
		ollamaMessages = []api.Message{
			api.Message{
				Role:    "system",
				Content: prompt,
			},
		}

	} else {
		messages = []openai.ChatCompletionMessage{
			{
				Role:    openai.ChatMessageRoleUser,
				Content: prompt,
			},
		}

		if len(config.Input.Prompt) != 0 {
			message := openai.ChatCompletionMessage{
				Role:    openai.ChatMessageRoleUser,
				Content: config.Input.Prompt,
			}
			messages = append(messages, message)
			fmt.Println("-> ", config.Input.Prompt)
		}
	}
	return nil
}

// queryAI handles user queries and generates responses based on the selected AI provider
func queryAI(prompt string) string {
	text := strings.Replace(prompt, "\n", "", -1)
	if text == "quit" {
		return ""
	}

	messages = append(messages, openai.ChatCompletionMessage{
		Role:    openai.ChatMessageRoleUser,
		Content: text,
	})

	var response string
	switch currentAIProvider.LLM {
	case "ChatGPT":
		resp, err := client.CreateChatCompletion(
			context.Background(),
			openai.ChatCompletionRequest{
				Model:    currentAIProvider.Model,
				Messages: messages,
			},
		)
		if err != nil {
			fmt.Printf("ChatCompletion error: %v\n", err)
			return ""
		}
		response = resp.Choices[0].Message.Content
	case "Ollama":
	case "Gemini":
		// resp, err := geminiClient.GenerateText(context.Background(), generativeai.GenerateTextRequest{
		// 	Model:  currentAIProvider.Model,
		// 	Prompt: text,
		// })
		// if err != nil {
		// 	fmt.Printf("Gemini error: %v\n", err)
		// 	return ""
		// }
		// response = resp.Text
		p := prompt
		// convert CRLF to LF
		p = strings.Replace(p, "\n", "", -1)
		// if p == "quit" {
		// 	return
		// }
		// fmt.Println(prompt)

	default:
		response = "Unsupported LLM selected"
	}

	messages = append(messages, openai.ChatCompletionMessage{
		Role:    openai.ChatMessageRoleAssistant,
		Content: response,
	})

	return response
}

func queryOllama(prompt string) string {
	p := prompt
	// convert CRLF to LF
	p = strings.Replace(p, "\n", "", -1)
	ollamaMessages = append(ollamaMessages, api.Message{
		Role:    "user",
		Content: p,
	})

	ctx := context.Background()
	req := &api.ChatRequest{
		Model:    currentAIProvider.Model,
		Messages: ollamaMessages,
	}

	var response string

	respFunc := func(resp api.ChatResponse) error {
		// fmt.Print(resp.Message.Content)
		response += resp.Message.Content
		// fmt.Println("response=", response)
		return nil
	}

	err := ollamaClient.Chat(ctx, req, respFunc)
	if err != nil {
		log.Fatal(err)
	}
	// fmt.Println("response=", response)
	return response
}

func queryGemini(prompt string) genai.Part {
	p := prompt
	// convert CRLF to LF
	p = strings.Replace(p, "\n", "", -1)
	// if p == "quit" {
	// 	return
	// }
	// fmt.Println(prompt)
	resp, err := cs.SendMessage(ctx, genai.Text(p))
	if err != nil {
		log.Fatal(err)
	}
	// // Process AI analysis results
	var text genai.Part
	if resp != nil {
		// Extract analysis candidates from response
		candidates := resp.Candidates

		// Process each analysis perspective
		// Example output: "High frequency of failed authentication attempts"
		for _, candidate := range candidates {
			// Similarly, you can access other fields of the Candidate
			content := candidate.Content
			if content != nil {
				// Access field of the Content struct
				// For example, if Content has Text field
				text = content.Parts[0]
				// Use the text variable
				// log.Println("Gemini AI Response:", text)
			}
		}
	}
	return text
}

// HandleWebPage initializes the web interface and routes
func HandleWebPage() {
	http.HandleFunc("/", handler)
	http.HandleFunc("/chat", chatHandler)
	http.HandleFunc("/upload", uploadHandler)
	http.HandleFunc("/upload-directory", uploadDirectoryHandler)
	http.HandleFunc("/analyze", analyzeHandler)

	port := "8080"
	url := "http://localhost:" + port
	fmt.Println("Server running at", url)
	go openBrowser(url)
	http.ListenAndServe(":"+port, nil)
}

// analyzeHandler handles the selection of LLM and Model
func analyzeHandler(w http.ResponseWriter, r *http.Request) {
	var reqData struct {
		LLM   string `json:"llm"`
		Model string `json:"model"`
	}

	err := json.NewDecoder(r.Body).Decode(&reqData)
	if err != nil {
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	currentAIProvider = AIProvider{LLM: reqData.LLM, Model: reqData.Model}
	fmt.Printf("Selected LLM: %s, Model: %s\n", reqData.LLM, reqData.Model)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

// chatHandler processes incoming chat API requests
func chatHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST requests are allowed", http.StatusMethodNotAllowed)
		return
	}

	var reqData struct {
		Query string `json:"query"`
	}

	err := json.NewDecoder(r.Body).Decode(&reqData)
	if err != nil {
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	if currentAIProvider.LLM == "Gemini" {
		response := queryGemini(reqData.Query)
		json.NewEncoder(w).Encode(map[string]genai.Part{"response": response})
	} else if currentAIProvider.LLM == "Ollama" {
		response := queryOllama(reqData.Query)
		json.NewEncoder(w).Encode(map[string]string{"response": response})
	} else {
		response := queryAI(reqData.Query)
		json.NewEncoder(w).Encode(map[string]string{"response": response})
	}

}

// uploadHandler processes file uploads
func uploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	r.ParseMultipartForm(10 << 20) // 10MB max memory

	file, handler, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Error retrieving file", http.StatusBadRequest)
		fmt.Println("Error retrieving file")
		return
	}
	defer file.Close()

	savePath := filepath.Join(os.TempDir(), handler.Filename)
	dst, err := os.Create(savePath)
	if err != nil {
		http.Error(w, "Error creating temporary file", http.StatusInternalServerError)
		fmt.Println("Error creating temporary file")
		return
	}
	defer dst.Close()

	if _, err := io.Copy(dst, file); err != nil {
		http.Error(w, "Error saving uploaded file", http.StatusInternalServerError)
		fmt.Println("Error saving uploaded file")
		return
	}

	fmt.Println("File saved at:", savePath)
	config.Input.Files = []string{savePath}
	decode.Process()

	if len(database.AI_Input) == 0 {
		http.Error(w, "Error reading file - No HTTP and SIP messages", http.StatusInternalServerError)
		fmt.Println("Error reading file - No HTTP and SIP messages")
		return
	}

	if err := Chatgpt_ai_process(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		fmt.Println("Error processing file")
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("File uploaded and processed successfully"))
}

// uploadDirectoryHandler processes directory uploads
func uploadDirectoryHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseMultipartForm(32 << 20) // 32MB max memory
	if err != nil {
		http.Error(w, "Unable to parse form", http.StatusBadRequest)
		return
	}

	files := r.MultipartForm.File["files"]
	uploadDir := "./uploads"
	if err := os.MkdirAll(uploadDir, os.ModePerm); err != nil {
		http.Error(w, "Unable to create upload directory", http.StatusInternalServerError)
		return
	}

	for _, fileHeader := range files {
		file, err := fileHeader.Open()
		if err != nil {
			http.Error(w, "Unable to open file", http.StatusInternalServerError)
			return
		}
		defer file.Close()

		dst, err := os.Create(filepath.Join(uploadDir, fileHeader.Filename))
		if err != nil {
			http.Error(w, "Unable to create file", http.StatusInternalServerError)
			return
		}
		defer dst.Close()

		if _, err := io.Copy(dst, file); err != nil {
			http.Error(w, "Unable to save file", http.StatusInternalServerError)
			return
		}
	}

	config.SaveDirectoryFiles(&uploadDir)
	decode.Process()

	if len(database.AI_Input) == 0 {
		http.Error(w, "Error reading file - No HTTP and SIP messages", http.StatusInternalServerError)
		return
	}

	if err := Chatgpt_ai_process(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Directory uploaded and processed successfully"))
}

// openBrowser launches the default web browser
func openBrowser(url string) {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "windows":
		cmd = "cmd"
		args = []string{"/c", "start"}
	case "darwin":
		cmd = "open"
	default:
		cmd = "xdg-open"
	}

	args = append(args, url)
	exec.Command(cmd, args...).Start()
}

func handler(w http.ResponseWriter, r *http.Request) {
	// Set response content type to HTML
	w.Header().Set("Content-Type", "text/html")

	// Define HTML template with styling and JavaScript
	html := `<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Powered Packet Analyser</title>
    <style>
        body {
            font-family: 'Plus Jakarta Sans', Arial, sans-serif;
            background-color: #f0f8ff; /* Light blue background */
            margin: 0;
            padding: 0;
            color: #1A365D;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
        }

        .header {
            width: 80%;
            max-width: 1000px;
            display: flex;
            align-items: center;
            gap: 20px;
            margin-bottom: 20px;
        }

        .logo {
            margin-right: auto;
            /* Push logo to the leftmost side */
        }

        .logo img {
            max-width: 150px;
            /* Adjust the size of your logo */
            height: auto;
        }

        .title {
            text-align: center;
            flex-grow: 1;
            /* Center the title */
        }

        h1 {
            margin: 0;
            color: #1C77B9;
            font-size: 2.5rem;
        }

        h2 {
            margin: 5px 0 20px 0;
            color: #4A5568;
            font-size: 1.2rem;
            font-weight: 400;
        }

        #uploadForm {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 20px;
        }

        #fileLabel {
            display: inline-block;
            padding: 10px 20px;
            border: 1px solid #E2E8F0;
            cursor: pointer;
            border-radius: 8px;
            background-color: #ffffff;
            color: #1C77B9;
            font-weight: 500;
            transition: background-color 0.3s ease;
        }

        #fileLabel:hover {
            background-color: #EFF4FB;
        }

        #directoryForm {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 20px;
        }

        #directoryLabel {
            display: inline-block;
            padding: 10px 20px;
            border: 1px solid #E2E8F0;
            cursor: pointer;
            border-radius: 8px;
            background-color: #ffffff;
            color: #1C77B9;
            font-weight: 500;
            transition: background-color 0.3s ease;
        }

        #directoryLabel:hover {
            background-color: #EFF4FB;
        }

        #chatContainer {
            width: 80%;
            max-width: 1000px;
            margin: 20px auto;
            background: #ffffff; /* White chat container */
            border-radius: 14px;
            box-shadow: 14px 17px 40px 4px rgba(112, 144, 176, 0.08);
            padding: 20px;
            min-height: 75vh;
            display: flex;
            flex-direction: column;
        }

        #chatbox {
            flex-grow: 1;
            overflow-y: auto;
            padding: 10px;
            border-bottom: 1px solid #E2E8F0;
            display: flex;
            flex-direction: column;
            gap: 10px;
        }

        .message {
            padding: 10px 15px;
            margin: 5px 0;
            border-radius: 8px;
            max-width: 70%;
            white-space: pre-line;
            position: relative;
        }

        .user {
            background: #E2E8F0;
            /* Gray for sender */
            align-self: flex-end;
            margin-left: auto;
        }

        .bot {
            background: transparent;
            /* No color for response */
            align-self: flex-start;
            margin-right: auto;
            border: 1px solid #E2E8F0;
            /* Optional: Add a border for clarity */
        }

        #inputContainer {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 10px;
        }

        textarea {
            flex-grow: 1;
            padding: 10px;
            border-radius: 8px;
            /* Less rounded */
            border: 1px solid #E2E8F0;
            font-size: 16px;
            resize: none;
            min-height: 50px;
            outline: none;
        }

        button {
            padding: 10px 20px;
            border: none;
            background: #1C77B9;
            /* Updated button color */
            color: white;
            font-size: 16px;
            border-radius: 8px;
            /* Less rounded */
            cursor: pointer;
            transition: background 0.3s ease;
        }

        button:hover {
            background: #155a8a;
            /* Darker shade for hover */
        }

        .file-upload {
            margin-top: 20px;
        }

        #filePath {
            margin-top: 10px;
            font-weight: bold;
        }

        .model-selection {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
        }

        .model-selection select {
            padding: 10px;
            border-radius: 8px;
            border: 1px solid #E2E8F0;
            font-size: 16px;
            background-color: #ffffff;
            color: #1C77B9;
            cursor: pointer;
        }

        .model-selection select:hover {
            background-color: #EFF4FB;
        }
    </style>
</head>

<body>
    <div class="header">
        <div class="logo">
            <img src="C:\Users\slganesh\Desktop\SIP-Project\Techtez.png" alt="Techtez">  </div>
        <div class="title">
            <h1>AI Powered Packet Analyser</h1>
            <h2>Upload a PCAP and Chat to analyse</h2>
        </div>
    </div>

    <!-- Model Selection Dropdowns -->
    <div class="model-selection">
        <select id="category" class="form-control form-select" onchange="filterOptions()">
            <option value="">Select LLM</option>
            <option value="ChatGPT">ChatGPT</option>
            <option value="Ollama">Ollama</option>
            <option value="Gemini">Gemini</option>
        </select>
        <select id="items" class="form-control form-select">
            <option value="">Select Model</option>
            <option data-category="ChatGPT" value="gpt-4-turbo">GPT-4</option>
            <option data-category="ChatGPT" value="gpt-4o">GPT-4o</option>
            <option data-category="Ollama" value="llama3">LLAMA-3</option>
            <option data-category="Ollama" value="mistral">MISTRAL</option>
            <option data-category="Ollama" value="gemma3">GEMMA3</option>
            <option data-category="Gemini" value="gemini-1.5-flash">gemini-1.5-flash</option>
            <option data-category="Gemini" value="gemini-2-flash">GEMINI2-FLASH</option>
            <option data-category="Gemini" value="gemini-2-pro">GEMINI2-PRO</option>
        </select>
        <button onclick="sendSelection()">Submit</button>
    </div>

    <!-- File Upload Forms -->
    <form id="uploadForm" enctype="multipart/form-data">
        <input type="file" id="fileInput" name="file" required onchange="showFileName()" hidden />
        <label id="fileLabel" for="fileInput">Choose File</label>
        <button type="button" onclick="uploadFile()">Upload</button>
    </form>
    <form id="directoryForm" enctype="multipart/form-data">
        <input type="file" id="directoryInput" name="directory" webkitdirectory directory required onchange="showDirectoryPath()" hidden />
        <label id="directoryLabel" for="directoryInput">Choose Directory</label>
        <button type="button" onclick="uploadDirectory()">Upload Directory</button>
    </form>

    <!-- Chat Container -->
    <div id="chatContainer">
        <div id="chatbox"></div>
        <div id="inputContainer">
            <textarea id="userInput" placeholder="Type your message..." oninput="autoExpand(this)"></textarea>
            <button onclick="sendMessage()">Send</button>
        </div>
    </div>

    <script>
        // Model Selection Logic
        function filterOptions() {
            const category = document.getElementById('category').value;
            const items = document.getElementById('items');
            const options = items.querySelectorAll('option');

            items.value = ""; // Reset selected model

            options.forEach(option => {
                if (!category || option.dataset.category === category || option.value === "") {
                    option.style.display = 'block';
                } else {
                    option.style.display = 'none';
                }
            });
        }

        function sendSelection() {
            const category = document.getElementById('category').value;
            const model = document.getElementById('items').value;

            if (!category || !model) {
                alert("Please select both LLM and Model.");
                return;
            }

            fetch("/analyze", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ llm: category, model: model })
            })
                .then(response => {
                    if (response.ok) {
                        alert("Analysis started with LLM: " + category + ", Model: " + model);
                    } else {
                        alert("Error starting analysis.");
                    }
                })
                .catch(error => {
                    alert("Error: " + error);
                });
        }

        // File and Directory Upload Logic
        function showDirectoryPath() {
            const directoryInput = document.getElementById("directoryInput");
            const directoryLabel = document.getElementById("directoryLabel");
            if (directoryInput.files.length > 0) {
                directoryLabel.innerText = directoryInput.files[0].webkitRelativePath.split('/')[0];
            }
        }

        function uploadDirectory() {
            const directoryInput = document.getElementById("directoryInput");

            if (directoryInput.files.length === 0) {
                alert("Please select a directory.");
                return;
            }

            const formData = new FormData();
            for (const file of directoryInput.files) {
                formData.append("files", file);
            }

            fetch("/upload-directory", {
                method: "POST",
                body: formData
            })
                .then(response => {
                    if (response.ok) {
                        alert("Directory uploaded successfully!");
                    } else {
                        alert("Error uploading directory.");
                    }
                })
                .catch(error => {
                    alert("Error: " + error);
                });
        }

        function uploadFile() {
            let fileInput = document.getElementById("fileInput");

            if (fileInput.files.length === 0) {
                alert("Please select a file.");
                return;
            }

            let formData = new FormData();
            formData.append("file", fileInput.files[0]);

            alert(formData.get("file").name);

            fetch("/upload", {
                method: "POST",
                body: formData
            })
                .then(response => {
                    alert(response.statusText);
                    if (response.ok) {
                        alert("File uploaded successfully!");

                        // Keep the filename visible
                        let fileName = fileInput.files[0].name;
                        let label = document.getElementById("fileLabel");
                        label.innerText = fileName; // Show filename in label

                    } else {
                        alert("Error reading file - No HTTP and SIP messages.");
                    }
                })
                .catch(error => {
                    alert("Error: " + error);
                });
        }

        function showFileName() {
            let fileInput = document.getElementById("fileInput");
            let label = document.getElementById("fileLabel");
            if (fileInput.files.length > 0) {
                label.innerText = fileInput.files[0].name; // Show selected file name
            }
        }

        // Chat Logic
        function sendMessage() {
            const inputField = document.getElementById("userInput");
            const chatbox = document.getElementById("chatbox");
            let userMessage = inputField.value.trim();
            if (!userMessage) return;

            // Display user message
            let userDiv = document.createElement("div");
            userDiv.className = "message user";
            userDiv.textContent = userMessage;
            chatbox.appendChild(userDiv);
            inputField.value = "";
            autoExpand(inputField);

            // Send message to backend
            fetch("/chat", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ query: userMessage })
            })
                .then(response => response.json())
                .then(data => {
                    // Display bot response
                    let botDiv = document.createElement("div");
                    botDiv.className = "message bot";
                    botDiv.textContent = data.response;
                    chatbox.appendChild(botDiv);
                    chatbox.scrollTop = chatbox.scrollHeight;
                })
                .catch(err => console.error("Error:", err));
        }

        function autoExpand(textarea) {
            textarea.style.height = "50px"; // Reset height
            textarea.style.height = textarea.scrollHeight + "px"; // Set new height
        }
    </script>
</body>

</html>`
	// Write the HTML to the response
	w.Write([]byte(html))
}
