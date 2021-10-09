# authentication
a package for authentication in Go using sqlite3

## About:
- authentication uses a sha256 hash and a salt to generate password hashes. salts are randomized strings, and and are appended/prepended to the password.

- authentication offers a good way to make cookies that expire every day. the cookie is a combination of the user's ID and salt, as well as the date. this causes cookies to expire when the date changes, but also offers a really good way to present authentication information to the API. We use the userID presented to generate our own cookie string and check against that.

## Requirements:
Go (1.17+, but any version should work)
sqlite3 - you'll also need to configure a table for Users

## Notes:
- the User struct should be reworked to match your schema, but will probably fit your use case (if it doesn't, let me know). It carries an Err with it, which we use for the password authentication section. The warnings in this section are intentionally vague to keep potential attackers from finding out anything useful. The errors can be put into a template as a warning for the login, or logged. However you want it.

- the format in GenerateCookie can be changed, it's probably unnecessarily complex, but I do recommend leaving the userID in (although you don't need to). I see how it's a potential vulnerability to let an attacker know our UserID, but the hash in the cookie should be sufficiently complex to thwart attacks. The scheme here should be complex enough to thwart attacks even if an attacker somehow got our .db file.

- use the Entry.Tries variable to lock out an account after n unsuccessful attempts. On unsuccessful attempts, IncrementTries. When a user successfully logs in, ResetTries(). 