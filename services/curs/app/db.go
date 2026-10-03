package main

import (
	"database/sql"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
)

func InitDB() (*sql.DB, error) {
	db, err := sql.Open("mysql", "root:secret@tcp(db:3306)/curs")
	if err != nil {
		return nil, fmt.Errorf("ошибка при открытии БД: %w", err)
	}

	err = db.Ping()
	if err != nil {
		return nil, fmt.Errorf("ошибка при пинге БД: %w", err)
	}
	return db, nil
}
