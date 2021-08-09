package outputter

import (
	"fmt"
	"os"
	"time"

	"github.com/aquasecurity/bench-common/check"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// PgSQL contains the database connection information
type PgSQL struct {
	host     string
	user     string
	password string
	sslMode  string
	dbName   string
}

const (
	// HOST host key
	HOST = "HOST"
	// USER key
	USER = "USER"
	// PASSWORD key
	PASSWORD = "PASSWORD"
	// SSLMODE key
	SSLMODE = "SSLMODE"
	// DBNAME key
	DBNAME = "DBNAME"
)

// NewPgSQL constructs a new PgSQL
func NewPgSQL(configValues map[string]string) *PgSQL {
	return &PgSQL{
		host:     configValues[HOST],
		user:     configValues[USER],
		password: configValues[PASSWORD],
		sslMode:  configValues[SSLMODE],
		dbName:   configValues[DBNAME],
	}
}

// Output stores JSON payload to the database
func (pg *PgSQL) Output(controls *check.Controls, summary check.Summary) error {
	jsonPayload, err := controls.JSON()
	if err != nil {
		return fmt.Errorf("unable to save PostgreSQL data - %v", err)
	}

	connInfo := fmt.Sprintf("host=%s user=%s dbname=%s sslmode=%s password=%s",
		pg.host,
		pg.user,
		pg.dbName,
		pg.sslMode,
		pg.password,
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

	db, err := gorm.Open(postgres.Open(connInfo), &gorm.Config{})
	if err != nil {
		return fmt.Errorf("unable to save PostgreSQL data - received error connecting to database: %v", err)
	}

	if err = db.Debug().AutoMigrate(&ScanResult{}); err != nil {
		return fmt.Errorf("unable to save PostgreSQL data - AutoMigrate: %v", err)
	}

	if err = db.Save(&ScanResult{ScanHost: hostname, ScanTime: time.Now(), ScanInfo: string(jsonPayload)}).Error; err != nil {
		return fmt.Errorf("unable to save PostgreSQL data - Save: %v", err)
	}

	return nil
}
