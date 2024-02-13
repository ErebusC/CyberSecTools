package main

import (
	"fmt"
	"net/http"
	"html/template"
	"os"
	"log"
	"runtime"
	"os/exec"
)

type website struct {
	Site string
}

func main() {
	args := os.Args

	if len(args) == 2 {
		tmpl := template.Must(template.ParseFiles("website/index.html"))
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			data := website{
				Site: args[1],
			}

			tmpl.Execute(w, data)
		})

		http.Handle("/website/", http.StripPrefix("/website/", http.FileServer(http.Dir("website"))))
		http.ListenAndServe(":9999", nil)
	} else {
		http.Handle("/", http.FileServer(http.Dir("./website")))
		http.ListenAndServe(":9999", nil)
	}

	openBrowser("http://localhost:9999")
	
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