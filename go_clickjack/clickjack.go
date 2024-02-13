package main

import (
	"net/http"
	"html/template"
	"os"
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
		http.ListenAndServe(":9999", nil)
	} else {
		http.Handle("/", http.FileServer(http.Dir("./website")))
		http.ListenAndServe(":9999", nil)
	}
	
}