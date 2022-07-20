# authentication

## About:
package authentication is a simple way to handle authentication for any site. open your sqlite3 database (or any other *sql.DB, really) and use it in the queries you send to the authentication functions. comes with sane defaults for a secure site, and a way to serve cookies if desired.

## Important Notes:
* on first run (or every run) be sure to run GenerateUserTable so your users have a place to go.

* if you choose to define your own PasswordScheme, be sure to do it before creating any users (or be prepared to reset some passwords). 

## The PasswordScheme interface:
the PasswordScheme interface can be used to override the default password generation/salting scheme. To use, define your own struct that is also a PasswordScheme, then in your main program change the declaration of authentication.PasswordSaltingScheme to a default-constructed struct of that type. You can use the passwordscheme.go file as a reference, but the defaults are sane and secure. 
```go
import (
    "github.com/sharkpick/authentication"
)

func main() {
    authentication.PasswordSaltingScheme = MyCustomPasswordSaltingScheme{}
    // proceed as normal
}
```

## Cookies:
the default `BasicScheme::GenerateCookie()` method generates cookies that are only valid until 11:59 Today, by server time. This is secure, and works well if your server and users are in the same time zone, but if that's not the case you could declare your own PasswordScheme and generate cookies differently. see passwordssccheme.go to see how it's done by default for an example.

### Exported Cookie Variables
The following are exported for easy modification - they may be necessary to change if you choose to create your own PasswordScheme.
* `var authentication.CookiesSameSiteMode http.SameSite` - default is strict.
* `var CookiesExpireTime time.Duration` - default maximum is 24 hours
* `var CookiesPath string` - default is "/"
* `var CookieName string` - default is "usercookies"

## Middleware
I suggest adding some middleware to add authentication.User structs to your request, this can make it really simple to authenticate a request down the line. use `authentication.SetCookies()` when a user first logs in for this to work.
```go
type RequestContextKey uint8

const (
    RequestContextUser RequestContextKey = iota
)

func addUserToRequest(next http.Handler) http.Handler {
    return http.HandleFunc(func(w http.ResponseWriter, r *http.Request) {
        cookies, err := r.Cookie(authentication.CookieName)
        if err == nil {
            user, err := authentication.CheckUserCookies(db, cookies.Value)
            if err == nil {
                ctx := context.WithValue(r.Context(), RequestContextUser, user)
                next.ServeHTTP(w, r.WithContext(ctx))
                return
            }
        }
        next.ServeHTTP(w, r)
    })
}
```
Then when required by your handlers you can get the user directly from the request. If it's nil the middleware did not find any cookies, and you should do something like redirect to your login page.
```go
func HandleSecretHandler(w http.ResponseWriter, r *http.Request) {
    user := r.Context().Value(RequestContextUser)
    if user == nil {
        http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
        return
    }
    log.Println("user", user.Username, "logged in")
}
```

## User Creation
calling `authentication.InsertUser()` will insert the user. the password in this case is the plaintext user input - the password is hashed and salted and never stored in plaintext.

## Logging In
calling `authentication.CheckUserLogin()` will return the authentication.User, if found, and a nil error. If the login failed, the user will be a default-constructed authentication.User and the error will explain what happened. 

when a user is logged in, I suggest using the `authentication.SetCookies()` function to store the cookies. This allows subsequent calls to `authentication.CheckUserCookies()` to find the authentication.User, effectively leaving a user logged in for the duration of their visit.