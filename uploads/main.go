package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

func openBrowser(url string) {
	var err error
	switch runtime.GOOS {
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	}
	if err != nil {
		fmt.Println("Error opening browser:", err)
	}
}

// HTML page with file upload functionality
func handler(w http.ResponseWriter, r *http.Request) {
	html := `
	<!DOCTYPE html>
	<html>
	<head>
		<title>Chat with ChatGPT</title>
		<style>
			body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
			h1 { font-size: 24px; }
			.chat-container { width: 400px; margin: 0 auto; }
			input { width: 300px; padding: 10px; border: 1px solid #ccc; border-radius: 5px; }
			button { padding: 10px 20px; background-color: blue; color: white; border: none; border-radius: 5px; cursor: pointer; }
			.file-upload { margin-top: 20px; }
		</style>
	</head>
	<body>
		<h1>Chat with ChatGPT</h1>
		<div class="chat-container">
			<input type="text" placeholder="Type your message..." />
			<button>Send</button>
		</div>

		<div class="file-upload">
			<h3>Upload a File</h3>
			<form action="/upload" method="post" enctype="multipart/form-data">
				<input type="file" name="file" required />
				<button type="submit">Import</button>
			</form>
		</div>
	</body>
	</html>`
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

// Handles file uploads
func uploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// Parse the form with max 10MB file size
	r.ParseMultipartForm(10 << 20)

	file, handler, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Error retrieving file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Save file to a temporary directory
	savePath := filepath.Join(os.TempDir(), handler.Filename)
	dst, err := os.Create(savePath)
	if err != nil {
		http.Error(w, "Error saving file", http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	// Copy the uploaded file to the created file
	if _, err := io.Copy(dst, file); err != nil {
		http.Error(w, "Error writing file", http.StatusInternalServerError)
		return
	}

	// Print the file path to the server logs
	fmt.Println("File saved at:", savePath)

	// Respond with success message
	fmt.Fprintf(w, "File uploaded successfully! Saved at: %s", savePath)
}

func main() {
	port := "8080"
	url := "http://localhost:" + port

	http.HandleFunc("/", handler)
	http.HandleFunc("/upload", uploadHandler)

	go openBrowser(url)

	fmt.Println("Server is running at", url)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		fmt.Println("Failed to start server:", err)
	}
}
