package authentication

import (
	"database/sql"
	"fmt"
)

// GenerateUserTable generates the default user table in the
// database. The table is necessary for proper functioning of
// this package.
func GenerateUserTable(db *sql.DB) error {
	sql_string := `CREATE TABLE IF NOT EXISTS "` + UsersTable + `"(
	"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
	"username" TEXT NOT NULL UNIQUE,
	"password" TEXT NOT NULL,
	"salt" TEXT NOT NULL,
	"tries" integer NOT NULL,
	"permissions" integer NOT NULL);`
	prepared, err := db.Prepare(sql_string)
	if err != nil {
		return fmt.Errorf("GenerateUserTable %w: %s", ErrSQLFailedPrepare, err)
	}
	_, err = prepared.Exec()
	if err != nil {
		return fmt.Errorf("GenerateUserTable %w: %s", ErrSQLFailedExecution, err)
	}
	return nil
}
