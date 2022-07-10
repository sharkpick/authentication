package authentication

type PermissionsLevel int8

const (
	Guest PermissionsLevel = iota
	Registered
	Admin
)

type User struct {
	ID          int64
	Username    string
	Password    string
	Salt        string
	Tries       int64
	Permissions PermissionsLevel
}
