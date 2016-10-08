package main

import (
	"fmt"
	"net/http"
	"strconv"
)

type loginData struct {
	Email    string
	Password string
}

func auth(sessionStore AuthStorer, w http.ResponseWriter, r *http.Request) {
	session, err := sessionStore.GetSession()
	if err != nil {
		http.Error(w, "Authentication required: "+err.Error(), http.StatusUnauthorized)
		if a, ok := err.(*AuthError); ok {
			fmt.Println(a.Trace())
		}
	} else {
		addUserHeader(session, w)
	}
}

func authBasic(sessionStore AuthStorer, w http.ResponseWriter, r *http.Request) {
	session, err := sessionStore.GetBasicAuth()
	if err != nil {
		w.Header().Set("WWW-Authenticate", "Basic realm='Endfirst.com'")
		http.Error(w, "Authentication required: "+err.Error(), http.StatusUnauthorized)
	} else {
		addUserHeader(session, w)
	}
}

func login(sessionStore AuthStorer, w http.ResponseWriter, r *http.Request) {
	run(sessionStore.Login, w)
}

func register(sessionStore AuthStorer, w http.ResponseWriter, r *http.Request) {
	run(sessionStore.Register, w)
}

func createProfile(sessionStore AuthStorer, w http.ResponseWriter, r *http.Request) {
	run(sessionStore.CreateProfile, w)
}

func updateEmail(sessionStore AuthStorer, w http.ResponseWriter, r *http.Request) {
	run(sessionStore.UpdateEmail, w)
}

func updatePassword(sessionStore AuthStorer, w http.ResponseWriter, r *http.Request) {
	run(sessionStore.UpdatePassword, w)
}

func verifyEmail(sessionStore AuthStorer, w http.ResponseWriter, r *http.Request) {
	run(sessionStore.VerifyEmail, w)
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
	w.Header().Add("X-User-Id", strconv.Itoa(session.UserId))
}
