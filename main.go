package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"golang.org/x/crypto/bcrypt"
)

const uploadDir = "./uploads"
var users = map[string]string{}


func main() {
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/upload", uploadHandler)
	http.HandleFunc("/files/", downloadHandler)
	http.HandleFunc("/delete/", deleteHandler)
	

	if _, err := os.Stat(uploadDir); os.IsNotExist(err) {
		os.Mkdir(uploadDir, os.ModePerm)
	}

	fmt.Println("Server started at :8080")
	http.ListenAndServe(":8080", nil)
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	htmlPath := filepath.Join("static", "index.html")
	http.ServeFile(w, r, htmlPath)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Server error, unable to create account.", 500)
			return
		}

		users[username] = string(hashedPassword)
		fmt.Fprintf(w, "User %s registered successfully!", username)
	} else {
		http.ServeFile(w, r, "static/register.html")
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")

		storedPassword, ok := users[username]
		if !ok {
			http.Error(w, "Invalid username or password", http.StatusUnauthorized)
			return
		}

		err := bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(password))
		if err != nil {
			http.Error(w, "Invalid username or password", http.StatusUnauthorized)
			return
		}

		session, _ := store.Get(r, "session-name")
		session.Values["authenticated"] = true
		session.Save(r, w)

		fmt.Fprintf(w, "User %s logged in successfully!", username)
	} else {
		http.ServeFile(w, r, "static/login.html")
	}
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	r.ParseMultipartForm(10 << 20) // limit upload size to 10 MB
	file, handler, err := r.FormFile("file")
	if err != nil {
		fmt.Println("Error retrieving file")
		http.Error(w, "Unable to process file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	dst, err := os.Create(filepath.Join(uploadDir, handler.Filename))
	if err != nil {
		fmt.Println("Error saving the file")
		http.Error(w, "Unable to save file", http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	if _, err := io.Copy(dst, file); err != nil {
		http.Error(w, "Unable to save file", http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "File uploaded successfully: %s\n", handler.Filename)
}

func downloadHandler(w http.ResponseWriter, r *http.Request) {
	fileName := r.URL.Path[len("/files/"):]

	if fileName == "" {
		http.Error(w, "File name is required", http.StatusBadRequest)
		return
	}

	filePath := filepath.Join(uploadDir, fileName)

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Disposition", "attachment; filename=" + fileName)
	w.Header().Set("Content-Type", "application/octet-stream")

	http.ServeFile(w, r, filePath)
}

func deleteHandler(w http.ResponseWriter, r *http.Request) {
	fileName := r.URL.Path[len("/delete/"):]
	filePath := filepath.Join(uploadDir, fileName)

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	err := os.Remove(filePath)
	if err != nil {
		http.Error(w, "Unable to delete file", http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "File deleted successfully: %s\n", fileName)
}