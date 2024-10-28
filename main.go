package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"golang.org/x/crypto/bcrypt"
	"github.com/gorilla/sessions"
	"html/template"
	"image"
	"image/jpeg"
	// "image/png"
	"golang.org/x/image/draw"
	"strings"
)

const uploadDir = "./uploads"
var users = map[string]string{}
var store = sessions.NewCookieStore([]byte("super-secret-key"))

type UploadPageData struct {
	Files []string
	Message string
}

func main() {
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)

	http.Handle("/upload", authMiddleware(http.HandlerFunc(uploadHandler)))
	http.Handle("/files/", authMiddleware(http.HandlerFunc(downloadHandler)))
	http.Handle("/delete/", authMiddleware(http.HandlerFunc(deleteHandler)))
	http.Handle("/view/", authMiddleware(http.HandlerFunc(viewHandler)))

	if _, err := os.Stat(uploadDir); os.IsNotExist(err) {
		os.Mkdir(uploadDir, os.ModePerm)
	}

	fmt.Println("Server started at :8080")
	http.ListenAndServe(":8080", nil)
}

func hasSuffix(fileName, suffix string) bool {
	return strings.HasSuffix(fileName, suffix)
}

func generateThumbnail(filePath string, thumbnailPath string, width int, fileExt string) error {
	switch fileExt {
	case ".png", ".jpg":
		file, err := os.Open(filePath)
		if err != nil {
			return err
		}
		defer file.Close()

		img, _, err := image.Decode(file)
		if err != nil {
			return err
		}

		newHeight := (img.Bounds().Dy() * width) / img.Bounds().Dx()
		resizedImg := image.NewRGBA(image.Rect(0, 0, width, newHeight))
		draw.NearestNeighbor.Scale(resizedImg, resizedImg.Bounds(), img, img.Bounds(), draw.Over, nil)

		thumbFile, err := os.Create(thumbnailPath)
		if err != nil {
			return err
		}
		defer thumbFile.Close()
		return jpeg.Encode(thumbFile, resizedImg, nil)
	
	case ".pdf":
		thumbFile, err := os.Create(thumbnailPath)
		if err != nil {
			return err
		}
		defer thumbFile.Close()

		pdfPlaceholder := image.NewRGBA(image.Rect(0, 0, width, width))
		return jpeg.Encode(thumbFile, pdfPlaceholder, nil)
	default:
		thumbFile, err := os.Create(thumbnailPath)
		if err != nil {
			return err
		}
		defer thumbFile.Close()

		txtPlaceholder := image.NewRGBA(image.Rect(0, 0, width, width))
		return jpeg.Encode(thumbFile, txtPlaceholder, nil)
	}
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	htmlPath := filepath.Join("static", "index.html")
	http.ServeFile(w, r, htmlPath)
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session-name")

		if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

type RegisterPageData struct {
	Message string
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")

		if _, exists := users[username]; exists {
			data := RegisterPageData{
				Message: "Username already taken. Please choose a different username.",
			}
			renderTemplate(w, "static/register.html", data)
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			data := RegisterPageData{
				Message: "Server error, unable to create account. Please try again.",
			}
			renderTemplate(w, "static/register.html", data)
			return
		}

		users[username] = string(hashedPassword)
		session, _ := store.Get(r, "session-name")

		session.Values["authenticated"] = true
		session.Save(r, w)
		http.Redirect(w, r, "/upload", http.StatusSeeOther)

	} else {
		data := RegisterPageData{
			Message: "",
		}
		renderTemplate(w, "static/register.html", data)
	}
}

type LoginPageData struct {
	Message string
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")

		storedPassword, ok := users[username]
		if !ok {
			data := LoginPageData{
				Message: "Invalid username or password.",
			}
			renderTemplate(w, "static/login.html", data)
			return
		}

		err := bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(password))
		if err != nil {
			data := LoginPageData{
				Message: "Invalid username or password.",
			}
			renderTemplate(w, "static/login.html", data)
			return
		}

		session, _ := store.Get(r, "session-name")
		session.Values["authenticated"] = true
		session.Save(r, w)

		http.Redirect(w, r, "/upload", http.StatusSeeOther)
	} else {
		data := LoginPageData{
			Message: "",
		}
		renderTemplate(w, "static/login.html", data)
	}
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		data := UploadPageData{
            Files: getUploadedFiles(),
            Message: "",
        }
        renderTemplate(w, "static/upload.html", data)
        return
	} else {
		r.ParseMultipartForm(10 << 20) // limit upload size to 10 MB
		file, handler, err := r.FormFile("file")
		if err != nil {
			data := UploadPageData{
				Files: getUploadedFiles(),
				Message: "Error retrieving file. Please try again.",
			}
			renderTemplate(w, "static/upload.html", data)
			return
		}
		defer file.Close()

		fileExt := strings.ToLower(filepath.Ext(handler.Filename))
		allowedExtensions := map[string]bool{".text": true, ".pdf": true, ".png": true, ".jpg": true}
		if !allowedExtensions[fileExt] {
			data := UploadPageData{
				Files: getUploadedFiles(),
				Message: "Invalid file type. Only .txt, .pdf, .png, and .jpg are allowed.",
			}
			renderTemplate(w, "static/upload.html", data)
			return
		}
	
		dst, err := os.Create(filepath.Join(uploadDir, handler.Filename))
		if err != nil {
			data := UploadPageData{
				Files: getUploadedFiles(),
				Message: "Error saving the file. Please try again.",
			}
			renderTemplate(w, "static/upload.html", data)
			return
		}
		defer dst.Close()
	
		if _, err := io.Copy(dst, file); err != nil {
			data := UploadPageData{
				Files: getUploadedFiles(),
				Message: "Error while copying file. Please try again.",
			}
			renderTemplate(w, "static/upload.html", data)
			return
		}
	
		data := UploadPageData{
			Files: getUploadedFiles(),
			Message: fmt.Sprintf("File uploaded successfully: %s", handler.Filename),
		}
		renderTemplate(w, "static/upload.html", data)
		return
	}
}

func renderTemplate(w http.ResponseWriter, templateFile string, data interface{}) {
	tmpl, err := template.ParseFiles(templateFile)
	if err != nil {
		http.Error(w, "Unable to load page", http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, data)
}

func renderTemplateWithSuffix(w http.ResponseWriter, templateFile string, data interface{}) {
    tmpl, err := template.New("template").Funcs(template.FuncMap{
        "hasSuffix": hasSuffix,
    }).ParseFiles(templateFile)
    if err != nil {
        http.Error(w, "Unable to load page", http.StatusInternalServerError)
        return
    }
    tmpl.Execute(w, data)
}

func getUploadedFiles() []string {
	files, err := os.ReadDir(uploadDir)
	if err != nil {
		return nil
	}

	var fileNames []string
	for _, file := range files {
		if !file.IsDir() {
			fileNames = append(fileNames, file.Name())
		}
	}
	return fileNames
}

func viewHandler(w http.ResponseWriter, r *http.Request) {
	fileName := r.URL.Path[len("/view/"):]
	filePath := filepath.Join(uploadDir, fileName)

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	http.ServeFile(w, r, filePath)
}

func downloadHandler(w http.ResponseWriter, r *http.Request) {
	fileName := r.URL.Path[len("/files/"):]

	if fileName == "" {
		data := UploadPageData{
			Files:   getUploadedFiles(),
			Message: "File name is required.",
		}
		renderTemplate(w, "static/upload.html", data)
		return
	}

	filePath := filepath.Join(uploadDir, fileName)

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		data := UploadPageData{
			Files:   getUploadedFiles(),
			Message: "File not found.",
		}
		renderTemplate(w, "static/upload.html", data)
		return
	}

	w.Header().Set("Content-Disposition", "attachment; filename=" + fileName)
	w.Header().Set("Content-Type", "application/octet-stream")

	http.ServeFile(w, r, filePath)
}

func deleteHandler(w http.ResponseWriter, r *http.Request) {
	fileName := r.URL.Path[len("/delete/"):]
	filePath := filepath.Join(uploadDir, fileName)

	var message string

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		message = "File not found."
	} else {
		err := os.Remove(filePath)
		if err != nil {
			message = "Unable to delete file."
		} else {
			message = fmt.Sprintf("File deleted successfully: %s", fileName)
		}
	}

	data := UploadPageData{
		Files: getUploadedFiles(),
		Message: message,
	}
	renderTemplate(w, "static/upload.html", data)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")

	session.Values["authenticated"] = false

	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusSeeOther)
}