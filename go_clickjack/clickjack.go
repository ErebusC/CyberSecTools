package main

import (
	"embed"
	"flag"
	"fmt"
	"html/template"
	"log"
	"mime"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type website struct {
	Site   string
	Collab string
	Logo   string
}

var (
	//go:embed html/*
	templatesFS embed.FS

	//go:embed static/*
	staticFS embed.FS
)

func main() {
	logoFlag := flag.String("logo", "", "Logo URL or local file path to display in the nav bar")
	flag.Parse()

	args := flag.Args()
	envVariable := os.Getenv("CONTAINER")

	logoURL, logoPath := resolveLogo(*logoFlag)

	if envVariable == "TRUE" {
		route(args, logoURL, logoPath)
	} else {
		go func() {
			for i := 0; i < 50; i++ {
				resp, err := http.Get("http://localhost:9999")
				if err == nil {
					resp.Body.Close()
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
			openBrowser("http://localhost:9999")
		}()
		route(args, logoURL, logoPath)
	}
}

// resolveLogo works out where the logo comes from.
// Returns (templateURL, localFilePath).
// If the logo is a remote URL, templateURL is set and localFilePath is empty.
// If the logo is a local file, localFilePath is set and templateURL is "/logo-img".
// If no logo is found, both are empty.
func resolveLogo(logoFlag string) (string, string) {
	if logoFlag != "" {
		if strings.HasPrefix(logoFlag, "http://") || strings.HasPrefix(logoFlag, "https://") {
			return logoFlag, ""
		}
		if _, err := os.Stat(logoFlag); err == nil {
			return "/logo-img", logoFlag
		}
		log.Printf("warning: logo file not found: %s", logoFlag)
		return "", ""
	}

	// Auto-detect a logo file next to the binary.
	exePath, err := os.Executable()
	if err != nil {
		return "", ""
	}
	dir := filepath.Dir(exePath)
	for _, name := range []string{"logo.svg", "logo.png", "logo.jpg", "logo.jpeg", "logo.gif"} {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err == nil {
			log.Printf("logo auto-detected: %s", path)
			return "/logo-img", path
		}
	}
	return "", ""
}

func route(args []string, logoURL string, logoPath string) {
	var staticFs = http.FS(staticFS)
	http.Handle("/static/", http.FileServer(staticFs))

	if logoPath != "" {
		lp := logoPath
		http.HandleFunc("/logo-img", func(w http.ResponseWriter, r *http.Request) {
			ext := strings.ToLower(filepath.Ext(lp))
			if mt := mime.TypeByExtension(ext); mt != "" {
				w.Header().Set("Content-Type", mt)
			}
			http.ServeFile(w, r, lp)
		})
	}

	targetURL := "https://economist.com"
	targetCollab := ""
	if len(args) >= 2 {
		targetURL = args[0]
		targetCollab = args[1]
	} else if len(args) >= 1 {
		targetURL = args[0]
	}

	frameResponse(targetURL, targetCollab, logoURL)
}

func frameResponse(targetURL string, targetCollab string, logoURL string) {
	tmpl := template.Must(template.ParseFS(templatesFS, "html/index.html"))
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "Deny")
		data := website{
			Site:   targetURL,
			Collab: targetCollab,
			Logo:   logoURL,
		}
		tmpl.Execute(w, data)
	})
	log.Println("Listening on :9999")
	http.ListenAndServe(":9999", nil)
}

// https://code-maven.com/slides/golang/open-web-browser
func openBrowser(targetURL string) {
	var err error
	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", targetURL).Start()
	case "windows":
		err = exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", targetURL).Start()
	case "darwin":
		err = exec.Command("open", targetURL).Start()
	default:
		err = fmt.Errorf("unsupported platform %v", runtime.GOOS)
	}
	if err != nil {
		log.Fatal(err)
	}
}
