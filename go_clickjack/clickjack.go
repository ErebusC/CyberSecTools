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
}

var (
	//go:embed html/*
	templatesFS embed.FS

	//go:embed static/*
	staticFS embed.FS

)

func main() {
	args := os.Args

	openBrowser("http://localhost:9999")


    var staticFs = http.FS(staticFS)
	staticFile := http.FileServer(staticFs)

	http.Handle("/static/", staticFile)

	if len(args) == 2 {
		frameResponse(args[1])
	} else {
		frameResponse("https://bing.co.uk")
	}

}	

func openBrowser(targetURL string) {
    var err error
    switch runtime.GOOS {
    case "linux":
        err = exec.Command("xdg-open", targetURL).Start()
        // TODO: "Windows Subsytem for Linux" is also recognized as "linux", but then we need
        // err = exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", targetURL).Start()
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

    func frameResponse(targetURL string) {
    	tmpl := template.Must(template.ParseFS(templatesFS, "html/index.html"))
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			data := website{
				Site: targetURL,
			}

			tmpl.Execute(w, data)
		})
		http.ListenAndServe(":9999", nil)
    }
