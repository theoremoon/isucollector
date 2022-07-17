package isucollector

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	_ "embed"

	"github.com/labstack/echo/v4"
	_ "github.com/mattn/go-sqlite3"
)

const (
	SQL_INIT = `
CREATE TABLE IF NOT EXISTS log (
    kind TEXT,
    content BLOB,
    revision STRING,
    created_at INTEGER
)
`
	SLOW_LOG_PATH   = "/var/log/mysql/slow-log.lsql"
	ACCESS_LOG_PATH = "/var/log/nginx/access.log"
	ALP_CONF_PATH   = "/tmp/alp.conf"
)

type IsuCollector struct {
	db   *sql.DB
	repo string

	DBPath     string
	SlowLog    string
	AccessLog  string
	ALPConf    string
	ALPCommand string
}

func New(repo string, dbpath string) *IsuCollector {
	db, err := sql.Open("sqlite3", dbpath)
	if err != nil {
		panic(err)
	}

	if _, err := db.Exec(SQL_INIT); err != nil {
		log.Println("initialize error: %w", err)
	}

	return &IsuCollector{
		db:         db,
		repo:       repo,
		DBPath:     dbpath,
		SlowLog:    SLOW_LOG_PATH,
		AccessLog:  ACCESS_LOG_PATH,
		ALPConf:    ALP_CONF_PATH,
		ALPCommand: "ltsv",
	}
}

func (c *IsuCollector) queryDigest() (io.Reader, error) {
	cmd := exec.Command("pt-query-digest", "--limit", "100%", "--output", "json", c.SlowLog)
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return bytes.NewBuffer(output), nil
}

func (c *IsuCollector) alp() (io.Reader, error) {
	cmd := exec.Command("alp", c.ALPCommand, "--config", c.ALPConf, "--file", c.AccessLog, "--format", "csv")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return bytes.NewBuffer(output), nil
}

func (c *IsuCollector) getRevision(dir string) (string, error) {
	cmd := exec.Command("git", "rev-parse", "HEAD")
	cmd.Dir = dir

	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func (c *IsuCollector) Cleanup() {
	os.Remove(c.AccessLog)
	os.Remove(c.SlowLog)
}

func (c *IsuCollector) Collect() {
	now := time.Now().Unix()

	revision, err := c.getRevision(c.repo)
	if err != nil {
		log.Println("failed to get revision: %w", err)
	}

	qr, err := c.queryDigest()
	if err == nil {
		digest, _ := io.ReadAll(qr)
		c.db.Exec("INSERT INTO log (kind, content, revision, created_at) VALUES (?, ?, ?, ?)", "pt-query-digest", string(digest), revision, now)
	} else {
		log.Println("pt-query-digest: %w", err)
	}

	ar, err := c.alp()
	if err == nil {
		alp, _ := io.ReadAll(ar)
		c.db.Exec("INSERT INTO log (kind, content, revision, created_at) VALUES (?, ?, ?, ?)", "alp", string(alp), revision, now)
	} else {
		log.Println("alp: %w", err)
	}
}

type Revision struct {
	Revision  string `json:"revision"`
	CreatedAt int64  `json:"created_at"`
}

func (c *IsuCollector) ListRevisions() ([]Revision, error) {
	rows, err := c.db.Query("SELECT revision, created_at FROM log GROUP BY revision, created_at ORDER BY created_at DESC")
	if err != nil {
		return nil, fmt.Errorf("failed to select: %w", err)
	}

	revs := make([]Revision, 0)
	for rows.Next() {
		rev := Revision{}
		if err := rows.Scan(&rev.Revision, &rev.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan: %w", err)
		}

		revs = append(revs, rev)
	}
	return revs, nil
}

func (c *IsuCollector) GetDataOf(kind string, created_at int64) (string, error) {
	rows, err := c.db.Query("SELECT content FROM log WHERE kind = ? AND created_at = ?", kind, created_at)
	if err != nil {
		return "", fmt.Errorf("failed to select: %w", err)
	}

	for rows.Next() {
		content := ""
		if err := rows.Scan(&content); err != nil {
			return "", fmt.Errorf("failed to scan: %w", err)
		}

		return content, nil
	}
	return "", fmt.Errorf("no such data")
}

//go:embed index.html
var indexHTML []byte

func (c *IsuCollector) IndexHandler() http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Write(indexHTML)
	})
}

func (c *IsuCollector) RevisionsHandler() http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		revs, err := c.ListRevisions()
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}

		rw.Header().Set("Content-Type", "application/json")
		json.NewEncoder(rw).Encode(revs)
	})
}

func (c *IsuCollector) GetAlpHandler() http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		created_at, err := strconv.ParseInt(r.URL.Query().Get("created_at"), 10, 64)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}

		data, err := c.GetDataOf("alp", created_at)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}

		rw.Header().Set("Content-Type", "text/csv")
		json.NewEncoder(rw).Encode(data)
	})
}

func (c *IsuCollector) GetDigestHandler() http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		created_at, err := strconv.ParseInt(r.URL.Query().Get("created_at"), 10, 64)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}

		data, err := c.GetDataOf("pt-query-digest", created_at)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}

		rw.Header().Set("Content-Type", "application/json")
		rw.Write([]byte(data))
	})
}

func (c *IsuCollector) EchoIntegrate(e *echo.Echo) {
	e.GET("/debug", echo.WrapHandler(c.IndexHandler()))
	e.GET("/debug/pt-query-digest", echo.WrapHandler(c.GetDigestHandler()))
	e.GET("/debug/alp", echo.WrapHandler(c.GetAlpHandler()))
	e.GET("/debug/revisions", echo.WrapHandler(c.RevisionsHandler()))
}
