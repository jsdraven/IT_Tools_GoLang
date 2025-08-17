package server_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jsdraven/IT_Tools_GoLang/pkg/server"
)

func TestWriteAttachment_Basic(t *testing.T) {
	data := []byte("hello world")
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://x/download", nil)
	opts := server.AttachmentOpts{Filename: "greeting.txt", ContentType: "text/plain", Size: int64(len(data))}

	if err := server.WriteAttachment(rr, req, bytes.NewReader(data), opts); err != nil {
		t.Fatalf("WriteAttachment: %v", err)
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	if got := rr.Header().Get("Content-Type"); got != "text/plain" {
		t.Fatalf("content-type %q", got)
	}
	if got := rr.Header().Get("Content-Disposition"); got == "" {
		t.Fatalf("missing Content-Disposition")
	}
	if got := rr.Header().Get("Content-Length"); got != "11" {
		t.Fatalf("Content-Length %q", got)
	}
	if got := rr.Body.String(); got != string(data) {
		t.Fatalf("body %q", got)
	}
}

func TestWriteAttachment_HEAD(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodHead, "http://x/file", nil)
	opts := server.AttachmentOpts{Filename: "file.bin", ContentType: "application/octet-stream", Size: 0}

	if err := server.WriteAttachment(rr, req, nil, opts); err != nil {
		t.Fatalf("WriteAttachment: %v", err)
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	if rr.Body.Len() != 0 {
		t.Fatalf("HEAD should have empty body")
	}
}

func TestWriteAttachment_UnknownSize(t *testing.T) {
	data := []byte("data")
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://x/file", nil)
	opts := server.AttachmentOpts{Filename: "file.bin", ContentType: "application/octet-stream", Size: -1}

	if err := server.WriteAttachment(rr, req, bytes.NewReader(data), opts); err != nil {
		t.Fatalf("WriteAttachment: %v", err)
	}
	if rr.Header().Get("Content-Length") != "" {
		t.Fatalf("unexpected Content-Length header")
	}
	if rr.Body.String() != string(data) {
		t.Fatalf("body mismatch")
	}
}
