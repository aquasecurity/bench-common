package outputter

import (
	"fmt"
	"os"
	"time"

	"github.com/aquasecurity/bench-common/check"
	"github.com/jinzhu/gorm"
)

// PSGSQL contains the database connection information
type PSGSQL struct {
	Host     string
	User     string
	Password string
	SSLMode  string
	DBName   string
}

const (
	HOST     = "HOST"
	USER     = "USER"
	PASSWORD = "PASSWORD"
	SSLMODE  = "SSLMODE"
	DBNAME   = "DBNAME"
)

// NewPSGSQL constructs a new PSGSQL
func NewPSGSQL(configValues map[string]string) *PSGSQL {
	return &PSGSQL{
		Host:     configValues[HOST],
		User:     configValues[USER],
		Password: configValues[PASSWORD],
		SSLMode:  configValues[SSLMODE],
		DBName:   configValues[DBNAME],
	}
}

// Output stores JSON payload to the database
func (pg *PSGSQL) Output(controls *check.Controls, summary check.Summary) error {
	jsonPayload, err := controls.JSON()
	if err != nil {
		return fmt.Errorf("unable to save PostgreSQL data - %v", err)
	}

	connInfo := fmt.Sprintf("host=%s user=%s dbname=%s sslmode=%s password=%s",
		pg.Host,
		pg.User,
		pg.DBName,
		pg.SSLMode,
		pg.Password,
	)

	hostname, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("unable to save PostgreSQL data - received error looking up hostname: %v", err)
	}

	type ScanResult struct {
		gorm.Model
		ScanHost string    `gorm:"type:varchar(63) not null"` // https://www.ietf.org/rfc/rfc1035.txt
		ScanTime time.Time `gorm:"not null"`
		ScanInfo string    `gorm:"type:jsonb not null"`
	}

	db, err := gorm.Open("postgres", connInfo)
	if err != nil {
		return fmt.Errorf("unable to save PostgreSQL data - received error connecting to database: %v", err)
	}
	defer db.Close()

	db.Debug().AutoMigrate(&ScanResult{})
	errs := db.GetErrors()
	if len(errs) > 0 {
		return fmt.Errorf("unable to save PostgreSQL data - AutoMigrate: %v", errs)
	}

	db.Save(&ScanResult{ScanHost: hostname, ScanTime: time.Now(), ScanInfo: string(jsonPayload)})
	errs = db.GetErrors()
	if len(errs) > 0 {
		return fmt.Errorf("unable to save PostgreSQL data - Save: %v", errs)
	}

	return nil
}
