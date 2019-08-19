package outputter

import (
	"fmt"
	"os"
	"time"

	"github.com/aquasecurity/bench-common/check"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres" // database packages get blank imports
)

type Database struct{}

const (
	PgsqlHost     = "PGSQL_HOST"
	PgsqlUser     = "PGSQL_USER"
	PgsqlDBName   = "PGSQL_DBNAME"
	PgsqlSSLMode  = "PGSQL_SSLMODE"
	PgsqlPassword = "PGSQL_PASSWORD"
)

func (drp *Database) Output(controls *check.Controls, summary check.Summary, maybeConfig ...map[string]string) error {
	if len(maybeConfig) == 0 {
		return fmt.Errorf("Database - Config parameters are required\n")
	}
	config := maybeConfig[0]

	for k, v := range config {
		if v == "" {
			fmt.Errorf("Database - Config variable %s is missing", k)
		}
	}

	connInfo := fmt.Sprintf("host=%s user=%s dbname=%s sslmode=%s password=%s",
		config[PgsqlHost],
		config[PgsqlUser],
		config[PgsqlDBName],
		config[PgsqlSSLMode],
		config[PgsqlPassword],
	)

	out, err := controls.JSON()
	if err != nil {
		return fmt.Errorf("Database - Received error converting controls to JSON: %v", err)
	}
	jsonInfo := string(out)

	hostname, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("Database - Received error looking up hostname: %s", err)
	}

	timestamp := time.Now()

	type ScanResult struct {
		gorm.Model
		ScanHost string    `gorm:"type:varchar(63) not null"` // https://www.ietf.org/rfc/rfc1035.txt
		ScanTime time.Time `gorm:"not null"`
		ScanInfo string    `gorm:"type:jsonb not null"`
	}

	db, err := gorm.Open("postgres", connInfo)
	defer db.Close()
	if err != nil {
		return fmt.Errorf("Database - Received error connecting to database: %s", err)
	}

	db.Debug().AutoMigrate(&ScanResult{})
	db.Save(&ScanResult{ScanHost: hostname, ScanTime: timestamp, ScanInfo: jsonInfo})

	return nil
}
