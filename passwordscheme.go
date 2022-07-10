package authentication

import (
	"crypto/sha256"
	"fmt"
	"log"
	"math/rand"
	"strconv"
	"time"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

// PasswordScheme allows the user to use their own
// password salting scheme. Once set it must not be
// changed or the stored passwords in the database will
// not match the new scheme.
type PasswordScheme interface {
	GenerateSaltedPassword(string) (string, string)
	GenerateCookie(int64, string, string) string
	SaltedPassword(string, string) string
	GetIDFromCookie(string) int64
}

type BasicScheme struct {
}

func (b BasicScheme) GetIDFromCookie(cookie string) int64 {
	idString := cookie[:16]
	id, err := strconv.ParseInt(idString, 16, 64)
	if err != nil {
		log.Println("GetIDFromCookie error: invalid ID", idString, err)
		return -1
	}
	return id
}

func (b BasicScheme) GenerateSaltedPassword(password string) (hash, salt string) {
	salt = fmt.Sprintf("%08x", rand.Uint32())
	hash = b.SaltedPassword(password, salt)
	return
}

func (b BasicScheme) GenerateCookie(id int64, password, salt string) string {
	timestamp := time.Now().Format("2006-01-02")
	hashString := fmt.Sprintf("%s%s%s", password, salt, timestamp)
	hash := sha256.Sum256([]byte(hashString))
	theCookie := fmt.Sprintf("%016x%032x", id, hash)
	return theCookie
}

func (b BasicScheme) SaltedPassword(password, salt string) string {
	hashString := fmt.Sprintf("%s:%s", salt, password)
	hash := sha256.Sum256([]byte(hashString))
	return fmt.Sprintf("%032x", hash)
}
