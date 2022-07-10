package authentication

import (
	"net/http"
	"time"
)

func DeleteCookies(w http.ResponseWriter, CookieName string) {
	cookie := &http.Cookie{
		Name:    CookieName,
		Value:   "",
		Path:    "/",
		Expires: time.Now().Add(-(time.Hour * 24)),
	}
	http.SetCookie(w, cookie)
}

func SetCookies(w http.ResponseWriter, user User, CookieName string) {
	cookieVal := GenerateCookie(user.ID, user.Password, user.Salt)
	cookie := &http.Cookie{
		Name:    CookieName,
		Value:   cookieVal,
		Path:    "/",
		Expires: time.Now().Add(time.Hour * 24),
	}
	http.SetCookie(w, cookie)
}
