package handlers

import (
	"net/http"
)

var queryKey = "redirect_uri"

func doRedirect(w http.ResponseWriter, r *http.Request) {
	redirect := r.URL.Query().Get(queryKey)
	if redirect != "" {
		http.Redirect(w, r, redirect, http.StatusMovedPermanently)
	}
}
