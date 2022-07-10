# authentication

## About:
package authentication is a simple way to handle authentication for any site. simply open your sqlite3 database and use it in the queries you send to the authentication functions. comes with sane defaults for a secure site, and a way to serve cookies if desired.

## Usage:
on first run (or every run) be sure to run GenerateUserTable so your users have a place to go. The rest should be pretty intuitive, use the appropriate function to perform the desired action. examples will eventually be included.

the most interesting part (in my opinion) is the PasswordScheme interface that can be used with the global PasswordSaltingScheme variable in the authentication package to write your own authentication methods. all of the relevant parts of the formatting of your password/salt can be managed from this struct, the rest of the functions just use the strings that it produces. 