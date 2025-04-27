package db

import (
	"database/sql"
	"fmt"
	_ "github.com/lib/pq"
	config "proxy/cfg"
)

func Init(cfg *config.Config) (*sql.DB, error) {
	dbConfig := cfg.Postgres
	dataConnection := fmt.Sprintf("host=%s port=%s dbname=%s user=%s password=%s sslmode=disable",
		dbConfig.Host, dbConfig.Port, dbConfig.Database, dbConfig.Username, dbConfig.Password)
	fmt.Println(dataConnection)
	db, err := sql.Open("postgres", dataConnection)
	if err != nil {
		return nil, err
	}
	if err = db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping db: %w", err)
	}
	return db, nil
}
