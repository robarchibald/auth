package main

import (
	"fmt"
	"net/http"
)

// move together with nginxauth.go
func auth(authStore AuthStorer, w http.ResponseWriter, r *http.Request) {
	session, err := authStore.GetSession()
	if err != nil {
		http.Error(w, "Authentication required: "+err.Error(), http.StatusUnauthorized)
		if a, ok := err.(*AuthError); ok {
			fmt.Println(a.Trace())
		}
	} else {
		addUserHeader(session, w)
	}
}

func authBasic(authStore AuthStorer, w http.ResponseWriter, r *http.Request) {
	session, err := authStore.GetBasicAuth()
	if err != nil {
		w.Header().Set("WWW-Authenticate", "Basic realm='Endfirst.com'")
		http.Error(w, "Authentication required: "+err.Error(), http.StatusUnauthorized)
	} else {
		addUserHeader(session, w)
	}
}

func login(authStore AuthStorer, w http.ResponseWriter, r *http.Request) {
	run(authStore.Login, w)
}

func register(authStore AuthStorer, w http.ResponseWriter, r *http.Request) {
	run(authStore.Register, w)
}

func createProfile(authStore AuthStorer, w http.ResponseWriter, r *http.Request) {
	run(authStore.CreateProfile, w)
}

func updateEmail(authStore AuthStorer, w http.ResponseWriter, r *http.Request) {
	run(authStore.UpdateEmail, w)
}

func updatePassword(authStore AuthStorer, w http.ResponseWriter, r *http.Request) {
	run(authStore.UpdatePassword, w)
}

func verifyEmail(authStore AuthStorer, w http.ResponseWriter, r *http.Request) {
	run(authStore.VerifyEmail, w)
}

func run(method func() error, w http.ResponseWriter) {
	err := method()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		if a, ok := err.(*AuthError); ok {
			fmt.Println(a.Trace())
		}
	} else {
		w.Header().Add("Access-Control-Allow-Origin", "*")
		w.Header().Add("Content-Type", "application/javascript")
		fmt.Fprint(w, "{ \"result\": \"Success\" }")
	}
}

func addUserHeader(session *UserLoginSession, w http.ResponseWriter) {
	w.Header().Add("X-User", session.Email)
}
