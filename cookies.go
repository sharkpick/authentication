package authentication

import (
	"net/http"
	"time"
)

var (
	CookiesSameSiteMode = http.SameSiteStrictMode
	CookiesExpireTime   = time.Hour * 24
	CookiesPath         = "/"
	CookieName          = "usercookies"
)

func DeleteCookies(w http.ResponseWriter, CookieName string) {
	cookie := &http.Cookie{
		Name:    CookieName,
		Value:   "",
		Path:    CookiesPath,
		Expires: time.Now().Add(-CookiesExpireTime),
	}
	http.SetCookie(w, cookie)
}

func SetCookies(w http.ResponseWriter, user User) {
	cookieVal := GenerateCookie(user.ID, user.Password, user.Salt)
	cookie := &http.Cookie{
		Name:     CookieName,
		Value:    cookieVal,
		Path:     CookiesPath,
		Expires:  time.Now().Add(CookiesExpireTime),
		SameSite: CookiesSameSiteMode,
	}
	http.SetCookie(w, cookie)
}
