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
	requiredProperties []string = {
		PgsqlHost,
		PgsqlUser,
		PgsqlDBName,
		PgsqlSSLMode,
		PgsqlPassword,
	}
)

type DBConnectionOpenner interface {
	Open(dialect string, args ...interface{}) (db *gorm.DB, err error)
}

type GormConnectionOpenner struct {}

func (gco *GormConnectionOpenner) Open(dialect string, args ...interface{}) (db *gorm.DB, err error) {
	return gorm.Open("postgres", connInfo)
}


func (drp *Database) Output(controls *check.Controls, summary check.Summary, maybeConfig ...map[string]string) error {
	config, err := getFirstConfig(maybeConfig...)
	if err != nil {
		return fmt.Errorf("Database - %v", err)
	}

	if err := checkRequiredProperties(requiredProperties, config); err != nil {
		return fmt.Errorf("Database - %v", err)
	}

	connInfo := fmt.Sprintf("host=%s user=%s dbname=%s sslmode=%s password=%s",
		config[PgsqlHost],
		config[PgsqlUser],
		config[PgsqlDBName],
		config[PgsqlSSLMode],
		config[PgsqlPassword],
	)

	out, err := convertToJSON(controls)
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

	db, err := dbConnOpen(&GormConnectionOpenner{}, "postgres", connInfo)
	if err != nil {
		return fmt.Errorf("Database - Received error connecting to database: %s", err)
	}
	defer db.Close()

	db.Debug().AutoMigrate(&ScanResult{})
	db.Save(&ScanResult{ScanHost: hostname, ScanTime: timestamp, ScanInfo: jsonInfo})

	return nil
}

func checkRequiredProperties(requiredProps []string, config map[string]string) error {
	for _, k := range requiredProps {
		v, found := config[k]
		if !found || v == "" {
			return fmt.Errorf("Config variable %s is missing", k)
		}
	}
}

func dbConnOpen(d DBConnectionOpenner, dialect string, args ...interface{}) (db *gorm.DB, err error){
	return d.Open(dialect, args)
}
