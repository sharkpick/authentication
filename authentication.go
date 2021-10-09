package authentication

import (
	"crypto/sha256"
	"database/sql"
	"fmt"
	"log"
	"math/rand"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

type User struct {
	ID       int
	Username string
	Password string
	Salt     string
	Tries    int
	Err      error
}

func GetUserByID(db *sql.DB, id int) User {
	u := User{}
	if row, err := db.Query(fmt.Sprintf("SELECT * FROM users WHERE id='%d'", id)); err != nil {
		u.Err = fmt.Errorf("error: user not found")
	} else {
		defer row.Close()
		for row.Next() {
			row.Scan(&u.ID, &u.Username, &u.Password, &u.Salt, &u.Tries)
			return u
		}
	}
	u.Err = fmt.Errorf("error: user not found")
	return u
}

func InsertUser(db *sql.DB, username, password string) {
	pw, salt := GenerateSaltedPassword(password)
	sqlStatement := `INSERT INTO users(username, password, salt, tries) VALUES (?, ?, ?, ?)`
	if statement, err := db.Prepare(sqlStatement); err != nil {
		log.Fatalln("Fatal Error: couldn't insert user")
	} else {
		if _, err := statement.Exec(username, pw, salt, 0); err != nil {
			log.Fatalln("Fatal Error: couldn't exec statement to insert user", err)
		}
	}
}

func GenerateCookie(id int, password, salt string) string {
	// cookies = id:date+salt+password+salt
	timestamp := time.Now().Format("2006-01-02")
	hash := sha256.Sum256([]byte(fmt.Sprintf("%s%s%s%s", timestamp, salt, password, salt)))
	theCookie := fmt.Sprintf("%d:%032x", int64(id), hash)
	return theCookie
}

func GenerateSaltedPassword(password string) (string, string) {
	salt := fmt.Sprintf("%08x", rand.Uint32())
	hash := fmt.Sprintf("%032x", sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%s", salt, password, salt))))
	return hash, salt
}

func SaltedPassword(password, salt string) string {
	theHash := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%s", salt, password, salt)))
	return fmt.Sprintf("%032x", theHash)
}

func ResetTries(db *sql.DB, id int) {
	sqlStatement := `UPDATE users SET tries=0 WHERE id=?`
	db.Exec(sqlStatement, id)
}

func IncrementTries(db *sql.DB, id, tries int) {
	triesNow := tries + 1
	sqlStatement := `UPDATE users SET tries=? WHERE id=?`
	db.Exec(sqlStatement, triesNow, id)
}

func CheckUserLogin(db *sql.DB, username, password string) (bool, User) {
	log.Println("login attempt for", username)
	if row, err := db.Query(fmt.Sprintf("SELECT * FROM users WHERE username='%s'", username)); err != nil {
		return false, User{Err: fmt.Errorf("error: invalid username or password")}
	} else {
		defer row.Close()
		for row.Next() {
			u := User{}
			row.Scan(&u.ID, &u.Username, &u.Password, &u.Salt, &u.Tries)
			if username == u.Username {
				log.Println("found username:", username, "ID:", u.ID)
				if u.Tries > 5 {
					return false, User{Err: fmt.Errorf("error: account locked")}
				} else {
					if SaltedPassword(password, u.Salt) == u.Password {
						// reset tries
						go ResetTries(db, u.ID)
						log.Println("password verification passed")
						return true, u
					} else {
						go IncrementTries(db, u.ID, u.Tries)
						return false, User{Err: fmt.Errorf("invalid username or password")}
					}
				}
			}
		}
	}
	return false, User{Err: fmt.Errorf("invalid username or password")}
}
