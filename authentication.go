package authentication

import (
	"database/sql"
	"fmt"
)

const (
	UsersTable = "tUsers"
)

var (
	PasswordSaltingScheme PasswordScheme = BasicScheme{}
)

// Authentication errors
var (
	ErrUserNotFound       = fmt.Errorf("user not found")
	ErrInvalidPassword    = fmt.Errorf("invalid password")
	ErrAccountLocked      = fmt.Errorf("account locked")
	ErrInvalidCredentials = fmt.Errorf("invalid credentials")
	ErrEmptyCookies       = fmt.Errorf("invalid cookies")
	ErrInvalidUserID      = fmt.Errorf("invalid userid")
)

// Database errors
var (
	ErrSQLFailedPrepare   = fmt.Errorf("failed to prepare statement")
	ErrSQLFailedExecution = fmt.Errorf("failed to execute statement")
	ErrSQLFailedQuery     = fmt.Errorf("failed to query statement")
	ErrSQLFailedScan      = fmt.Errorf("failed to scan results to struct")
)

func GenerateSaltedPassword(password string) (string, string) {
	return PasswordSaltingScheme.GenerateSaltedPassword(password)
}

func GenerateCookie(id int64, password, salt string) string {
	return PasswordSaltingScheme.GenerateCookie(id, password, salt)
}

func GetIDFromCookie(cookie string) int64 {
	return PasswordSaltingScheme.GetIDFromCookie(cookie)
}

func SaltedPassword(password, salt string) string {
	return PasswordSaltingScheme.SaltedPassword(password, salt)
}

func UpdateUserPassword(db *sql.DB, username, password string) error {
	pw, salt := GenerateSaltedPassword(password)
	sql_string := "UPDATE " + UsersTable + " SET password=?, salt=? WHERE username=?"
	prepared, err := db.Prepare(sql_string)
	if err != nil {
		return fmt.Errorf("UpdateUserPassword %w: %s %s", ErrSQLFailedPrepare, sql_string, err)
	}
	_, err = prepared.Exec(pw, salt, username)
	if err != nil {
		return fmt.Errorf("UpdateUserPassword %w: %s %s", ErrSQLFailedExecution, sql_string, err)
	}
	return nil
}

func GetUserByID(db *sql.DB, id int64) (User, error) {
	var user User
	sql_string := "SELECT * FROM " + UsersTable + " WHERE id=?"
	prepared, err := db.Prepare(sql_string)
	if err != nil {
		return user, fmt.Errorf("GetUserByID %w: %s %s", ErrSQLFailedPrepare, sql_string, err)
	}
	row := prepared.QueryRow(id)
	err = row.Scan(&user.ID, &user.Username, &user.Password, &user.Salt, &user.Tries, &user.Permissions)
	if err != nil {
		return user, fmt.Errorf("GetUserByID %w: %s %s", ErrSQLFailedQuery, sql_string, err)
	}
	return user, nil
}

func InsertUser(db *sql.DB, username, password string) error {
	pw, salt := GenerateSaltedPassword(password)
	sql_string := "INSERT INTO " + UsersTable + "(username, password, salt, tries, permissions) VALUES (?, ?, ?, ?, ?)"
	prepared, err := db.Prepare(sql_string)
	if err != nil {
		return fmt.Errorf("InsertUser %w: %s %s", ErrSQLFailedPrepare, sql_string, err)
	}
	_, err = prepared.Exec(username, pw, salt, 0, Registered)
	if err != nil {
		return fmt.Errorf("InsertUser %w: %s %s", ErrSQLFailedExecution, sql_string, err)
	}
	return nil
}

func ResetTries(db *sql.DB, id int64) error {
	sql_string := "UPDATE " + UsersTable + " SET tries=0 WHERE id=?"
	prepared, err := db.Prepare(sql_string)
	if err != nil {
		return fmt.Errorf("ResetTries %w: %s %s", ErrSQLFailedPrepare, sql_string, err)
	}
	_, err = prepared.Exec(id)
	if err != nil {
		return fmt.Errorf("ResetTries %w: %s %s", ErrSQLFailedExecution, sql_string, err)
	}
	return nil
}

func IncrementTries(db *sql.DB, id, tries int64) error {
	triesNow := tries + 1
	sql_string := "UPDATE " + UsersTable + " SET tries=? WHERE id=?"
	prepared, err := db.Prepare(sql_string)
	if err != nil {
		return fmt.Errorf("IncrementTries %w: %s %s", ErrSQLFailedPrepare, sql_string, err)
	}
	_, err = prepared.Exec(triesNow, id)
	if err != nil {
		return fmt.Errorf("IncrementTries %w: %s %s", ErrSQLFailedExecution, sql_string, err)
	}
	return nil
}

func CheckUserCookies(db *sql.DB, cookie string) (User, error) {
	if len(cookie) == 0 {
		return User{}, fmt.Errorf("CheckUserCookies %w", ErrEmptyCookies)
	}
	id := GetIDFromCookie(cookie)
	if id < 0 {
		return User{}, fmt.Errorf("CheckUserCookies %w: %d %s", ErrInvalidUserID, id, cookie)
	}
	u, err := GetUserByID(db, id)
	if err != nil {
		return User{}, fmt.Errorf("CheckUserCookies %w: %s", ErrInvalidCredentials, err)
	}
	if GenerateCookie(u.ID, u.Password, u.Salt) != cookie {
		return User{}, fmt.Errorf("CheckUserCookies %w: %s", ErrInvalidCredentials, err)
	}
	return u, nil
}

func CheckUserLogin(db *sql.DB, username, password string) (User, error) {
	sql_string := "SELECT * FROM " + UsersTable + " WHERE username=?"
	prepared, err := db.Prepare(sql_string)
	if err != nil {
		return User{}, fmt.Errorf("CheckUserLogin %w: %s", ErrSQLFailedPrepare, err)
	}
	var user User
	row := prepared.QueryRow(username)
	err = row.Scan(&user.ID, &user.Username, &user.Password, &user.Salt, &user.Tries, &user.Permissions)
	fmt.Println("CheckUserLogin found user:", user)
	if err != nil {
		return User{}, fmt.Errorf("CheckUserLogin %w: %s", ErrSQLFailedScan, err)
	}
	if user.Username == username {
		if user.Tries > 5 {
			return User{}, fmt.Errorf("CheckUserLogin %w: %s", ErrAccountLocked, username)
		}
		if SaltedPassword(password, user.Salt) == user.Password {
			ResetTries(db, user.ID)
			return user, nil
		}
		IncrementTries(db, user.ID, user.Tries)
	}
	return User{}, fmt.Errorf("CheckUserLogin %w", ErrInvalidCredentials)
}
