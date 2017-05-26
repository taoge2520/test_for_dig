package models

//import (
//	"database/sql"
//	"fmt"
//	//	"strconv"
//	"time"

//	_ "github.com/go-sql-driver/mysql"
//)

//type Domain struct {
//	id     int
//	domain string
//	health int
//}

//func Open_db() (Db *sql.DB, err error) {
//	Db, err = sql.Open("mysql", Conn)
//	if err != nil {
//		return
//	}
//	Db.SetConnMaxLifetime(3600)

//	Db.Ping()
//	return Db, nil
//}

///*func checksqme(id int, db *sql.DB) bool {
//	var sql_id int
//	err := db.QueryRow("select id from domain_0_test where id=?", id).Scan(&sql_id)
//	if err != nil {
//		return false
//	}
//	if sql_id == 0 {
//		return false
//	}
//	return true

//}*/
//func Downtosql(v Domain, db *sql.DB, tb string) (err error) {
//	t := time.Now().Format("2006-01-02 15:04:05")
//	stmt, err := db.Prepare(`insert ` + tb + ` (id,domain,status,update_time)values(?,?,?,?)`)
//	defer stmt.Close()
//	if err != nil {
//		return err
//	}
//	_, err = stmt.Exec(v.id, v.domain, v.health, t)
//	if err != nil {
//		return err
//	}
//	return nil
//}
//func Getdomain1(begin int, end int, tb string) (re []Domain, err error) {
//	//select_start := strconv.Itoa(begin)
//	db, err := sql.Open("mysql", Conn)
//	defer db.Close()
//	if err != nil {
//		return
//	}
//	rows, err := db.Query(`select id ,domain ,health_status from `+tb+` where status in(1,2,3) and id>? and id<=?`, begin, end)
//	if err != nil {
//		return
//	}
//	defer rows.Close()
//	var t Domain
//	for rows.Next() {
//		rows.Scan(&t.id, &t.domain, &t.health)
//		re = append(re, t)
//	}
//	return

//}
//func Getdomain_ns() (ns []string, err error) {
//	db, err := sql.Open("mysql", Conn)
//	defer db.Close()
//	if err != nil {
//		fmt.Println(err)
//		return
//	}
//	rows, err := db.Query("select ns from domain_ns")
//	if err != nil {
//		fmt.Println(err)
//		return
//	}
//	defer rows.Close()
//	var str string
//	for rows.Next() {
//		rows.Scan(&str)
//		ns = append(ns, str+".")
//	}
//	return
//}

//func Sql_getcount(tb string) (id int, err error) {
//	db, err := sql.Open("mysql", Conn)
//	defer db.Close()
//	if err != nil {
//		return
//	}
//	rows, err := db.Query("SELECT max(id) from " + tb)
//	defer rows.Close()
//	if err != nil {
//		return
//	}

//	if rows.Next() {
//		rows.Scan(&id)
//		//checkErr(err)
//	}
//	return
//}
