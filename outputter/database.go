package outputter

import (
	"fmt"
	"os"
	"time"

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

// NewPSGSQL constructs a new PSGSQL
func NewPSGSQL(host, user, pwd, sslmode, dbname string) *PSGSQL {
	return &PSGSQL{
		Host:     host,
		User:     user,
		Password: pwd,
		SSLMode:  sslmode,
		DBName:   dbname,
	}
}

// Save stores JSON payload to the database
func (pg *PSGSQL) Save(jsonPayload string) error {
	connInfo := fmt.Sprintf("host=%s user=%s dbname=%s sslmode=%s password=%s",
		pg.Host,
		pg.User,
		pg.DBName,
		pg.SSLMode,
		pg.Password,
	)

	hostname, err := os.Hostname()
	if err != nil {
		fmt.Errorf("received error looking up hostname: %v", err)
	}

	timestamp := time.Now()

	type ScanResult struct {
		gorm.Model
		ScanHost string    `gorm:"type:varchar(63) not null"` // https://www.ietf.org/rfc/rfc1035.txt
		ScanTime time.Time `gorm:"not null"`
		ScanInfo string    `gorm:"type:jsonb not null"`
	}

	db, err := gorm.Open("postgres", connInfo)
	if err != nil {
		fmt.Errorf("received error connecting to database: %v", err)
	}
	defer db.Close()

	db.Debug().AutoMigrate(&ScanResult{})
	db.Save(&ScanResult{ScanHost: hostname, ScanTime: timestamp, ScanInfo: jsonPayload})

	return nil
}
