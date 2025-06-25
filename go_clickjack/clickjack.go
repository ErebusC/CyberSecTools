package main

import (
	"fmt"
	"net/http"
	"html/template"
	"os"
	"log"
	"runtime"
	"os/exec"
	"embed"
)

type website struct {
	Site string
	Collab string
}

var (
	//go:embed html/*
	templatesFS embed.FS

	//go:embed static/*
	staticFS embed.FS

)

func main() {
	args := os.Args
	envVariable := os.Getenv("CONTAINER")

	if envVariable == "TRUE"{
		route(args)
	} else {
		openBrowser("http://localhost:9999")
		route(args)
	}
}

func route(args []string){

	var staticFs = http.FS(staticFS)
	staticFile := http.FileServer(staticFs)

	http.Handle("/static/", staticFile)

	if len(args) >= 2 {
		frameResponse(args[1], args[2])
	} else {
		frameResponse("https://economist.com", "")
	}
}	

func frameResponse(targetURL string, targetCollab string) {
    tmpl := template.Must(template.ParseFS(templatesFS, "html/index.html"))
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "Deny")
		data := website{
			Site: targetURL,
			Collab: targetCollab,
		}

		tmpl.Execute(w, data)
	})
	http.ListenAndServe(":9999", nil)
}



//This was taken from here; https://code-maven.com/slides/golang/open-web-browser. 
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

