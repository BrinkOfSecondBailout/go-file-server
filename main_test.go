package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestRegisterHandler(t *testing.T) {
	// Initialize the users map to ensure a clean test environment
	users = make(map[string]string)

	// Create a form with sample username and password
	form := url.Values{}
	form.Set("username", "user123")
	form.Set("password", "user123")

	// Create a new HTTP POST request with the form data
	req, err := http.NewRequest("POST", "/register", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Record the HTTP response
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(registerHandler)

	// Call the handler with the recorder and request
	handler.ServeHTTP(rr, req)

	// Check if the status code is 200
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %v", rr.Code)
	}

	// Check if the user was registered by looking up the username in the map
	if _, exists := users["user123"]; !exists {
		t.Errorf("User 'user123' was not registered")
	}

	// Check if the correct file (upload.html) is served
	contentType := rr.Header().Get("Content-Type")
	if !strings.Contains(contentType, "text/html") {
		t.Errorf("Expected Content-Type text/html, got %v", contentType)
	}

	// Optionally, check for a specific element or text within the HTML response
	expectedContent := "<!DOCTYPE html>" // Replace with actual content in upload.html for accuracy
	if !strings.Contains(rr.Body.String(), expectedContent) {
		t.Errorf("Expected HTML response to contain %v, got %v", expectedContent, rr.Body.String())
	}

}