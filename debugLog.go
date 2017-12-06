package auth

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

func rlog(r *http.Request) {
	fmt.Println()
	fmt.Println(r.Method + ": " + r.URL.Path)
	for k, v := range r.Header {
		fmt.Println("header: ", k, ": ", v)
	}
	for k, v := range r.URL.Query() {
		fmt.Println("querystring: ", k, ": ", v)
	}
	if r.Method == "POST" {
		body, err := ioutil.ReadAll(r.Body)
		if err == nil {
			r.Body = ioutil.NopCloser(strings.NewReader(string(body)))
			fmt.Println("body: ", string(body))
		}
		r.ParseForm()
		for k, v := range r.Form {
			fmt.Println("form: ", k, ": ", v)
		}
	}
	for k, v := range r.Cookies() {
		fmt.Println("cookies: ", k, ": ", v)
	}
}
