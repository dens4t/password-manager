package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/argon2"
	uuid "github.com/satori/go.uuid"
)

var db *sql.DB

// Models
type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
	Salt     string `json:"salt"`
}

type PasswordEntry struct {
	ID       string `json:"id"`
	UserID   string `json:"user_id"`
	Title    string `json:"title"`
	Username string `json:"username"`
	Password string `json:"password"`
	URL      string `json:"url"`
	Notes    string `json:"notes"`
	Created  string `json:"created"`
	Updated  string `json:"updated"`
}

type AuthRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type PasswordRequest struct {
	Title    string `json:"title"`
	Username string `json:"username"`
	Password string `json:"password"`
	URL      string `json:"url"`
	Notes    string `json:"notes"`
}

// Security functions
func generateSalt() (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(salt), nil
}

func hashPassword(password, salt string) string {
	saltBytes, _ := base64.StdEncoding.DecodeString(salt)
	hash := argon2.IDKey([]byte(password), saltBytes, 1, 64*1024, 4, 32)
	return base64.StdEncoding.EncodeToString(hash)
}

func generateKey(masterKey string) []byte {
	hash := sha256.Sum256([]byte(masterKey))
	return hash[:]
}

func encryptPassword(password, masterKey string) (string, error) {
	key := generateKey(masterKey)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(password), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decryptPassword(encryptedPassword, masterKey string) (string, error) {
	key := generateKey(masterKey)
	data, err := base64.StdEncoding.DecodeString(encryptedPassword)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func generateToken(userID string) string {
	token := uuid.NewV4().String()
	hash := sha256.Sum256([]byte(token))
	return base64.StdEncoding.EncodeToString(hash[:])
}

// Database setup
func initDB() error {
	var err error
	db, err = sql.Open("sqlite3", "./securepass.db")
	if err != nil {
		return err
	}

	// Create users table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			password TEXT NOT NULL,
			salt TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return err
	}

	// Create passwords table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS passwords (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			title TEXT NOT NULL,
			username TEXT NOT NULL,
			password TEXT NOT NULL,
			url TEXT,
			notes TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
		)
	`)
	if err != nil {
		return err
	}

	// Create tokens table (simple session management)
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS tokens (
			token TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			expires_at DATETIME NOT NULL,
			FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
		)
	`)
	if err != nil {
		return err
	}

	// Create indexes
	_, err = db.Exec("CREATE INDEX IF NOT EXISTS idx_user_id ON passwords(user_id)")
	if err != nil {
		return err
	}

	_, err = db.Exec("CREATE INDEX IF NOT EXISTS idx_token_user ON tokens(user_id)")
	if err != nil {
		return err
	}

	return nil
}

// Middleware
func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token format"})
			c.Abort()
			return
		}

		// Verify token exists and hasn't expired
		var userID string
		var expiresAt time.Time
		err := db.QueryRow("SELECT user_id, expires_at FROM tokens WHERE token = ?", token).
			Scan(&userID, &expiresAt)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		if time.Now().After(expiresAt) {
			db.Exec("DELETE FROM tokens WHERE token = ?", token)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token expired"})
			c.Abort()
			return
		}

		c.Set("userID", userID)
		c.Next()
	}
}

// API Handlers
func registerHandler(c *gin.Context) {
	var req AuthRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Validate input
	if len(req.Username) < 3 || len(req.Username) > 50 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username must be 3-50 characters"})
		return
	}

	if len(req.Password) < 8 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password must be at least 8 characters"})
		return
	}

	// Check if user exists
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", req.Username).Scan(&count)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	if count > 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "Username already exists"})
		return
	}

	// Generate salt and hash password
	salt, err := generateSalt()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate salt"})
		return
	}

	hashedPassword := hashPassword(req.Password, salt)

	// Create user
	userID := uuid.NewV4().String()
	_, err = db.Exec(
		"INSERT INTO users (id, username, password, salt) VALUES (?, ?, ?, ?)",
		userID, req.Username, hashedPassword, salt,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "User created successfully"})
}

func loginHandler(c *gin.Context) {
	var req AuthRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Get user
	var user User
	err := db.QueryRow("SELECT id, username, password, salt FROM users WHERE username = ?", req.Username).
		Scan(&user.ID, &user.Username, &user.Password, &user.Salt)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Verify password
	hashedPassword := hashPassword(req.Password, user.Salt)
	if hashedPassword != user.Password {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Generate token
	token := generateToken(user.ID)
	expiresAt := time.Now().Add(24 * time.Hour)

	// Store token
	_, err = db.Exec("INSERT INTO tokens (token, user_id, expires_at) VALUES (?, ?, ?)",
		token, user.ID, expiresAt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create session"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": token})
}

func logoutHandler(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader != "" {
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token != "" {
			db.Exec("DELETE FROM tokens WHERE token = ?", token)
		}
	}
	c.JSON(http.StatusOK, gin.H{"message": "Logged out"})
}

func createPasswordHandler(c *gin.Context) {
	userID, _ := c.Get("userID")
	var req PasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Validate required fields
	if req.Title == "" || req.Username == "" || req.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Title, username, and password are required"})
		return
	}

	// Get user's master key (in real app, this would come from user session)
	// For demo, we'll use a simplified approach
	masterKey := userID.(string) + "_master"

	// Encrypt password
	encryptedPassword, err := encryptPassword(req.Password, masterKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encrypt password"})
		return
	}

	// Create password entry
	passwordID := uuid.NewV4().String()
	_, err = db.Exec(`
		INSERT INTO passwords (id, user_id, title, username, password, url, notes)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		passwordID, userID, req.Title, req.Username, encryptedPassword, req.URL, req.Notes,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save password"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": passwordID})
}

func getPasswordsHandler(c *gin.Context) {
	userID, _ := c.Get("userID")

	rows, err := db.Query(`
		SELECT id, title, username, password, url, notes, 
		       created_at, updated_at
		FROM passwords 
		WHERE user_id = ?
		ORDER BY updated_at DESC`, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch passwords"})
		return
	}
	defer rows.Close()

	var passwords []PasswordEntry
	for rows.Next() {
		var p PasswordEntry
		var encryptedPassword string
		err := rows.Scan(&p.ID, &p.Title, &p.Username, &encryptedPassword,
			&p.URL, &p.Notes, &p.Created, &p.Updated)
		if err != nil {
			continue
		}

		// In real app, we would decrypt here with user's master key
		// For security, we don't send decrypted passwords in list view
		p.Password = "********" // Masked for list view

		passwords = append(passwords, p)
	}

	c.JSON(http.StatusOK, passwords)
}

func getPasswordHandler(c *gin.Context) {
	userID, _ := c.Get("userID")
	passwordID := c.Param("id")

	var p PasswordEntry
	var encryptedPassword string
	err := db.QueryRow(`
		SELECT id, title, username, password, url, notes, created_at, updated_at
		FROM passwords 
		WHERE id = ? AND user_id = ?`,
		passwordID, userID).
		Scan(&p.ID, &p.Title, &p.Username, &encryptedPassword,
			&p.URL, &p.Notes, &p.Created, &p.Updated)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Password not found"})
		return
	}

	// Get master key and decrypt
	masterKey := userID.(string) + "_master"
	decryptedPassword, err := decryptPassword(encryptedPassword, masterKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decrypt password"})
		return
	}

	p.Password = decryptedPassword
	c.JSON(http.StatusOK, p)
}

func updatePasswordHandler(c *gin.Context) {
	userID, _ := c.Get("userID")
	passwordID := c.Param("id")

	var req PasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Check if password exists and belongs to user
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM passwords WHERE id = ? AND user_id = ?",
		passwordID, userID).Scan(&count)
	if err != nil || count == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Password not found"})
		return
	}

	// Encrypt password if provided
	var encryptedPassword string
	if req.Password != "" {
		masterKey := userID.(string) + "_master"
		encryptedPassword, err = encryptPassword(req.Password, masterKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encrypt password"})
			return
		}
	} else {
		// Keep existing password
		err = db.QueryRow("SELECT password FROM passwords WHERE id = ?", passwordID).
			Scan(&encryptedPassword)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get existing password"})
			return
		}
	}

	// Update password
	_, err = db.Exec(`
		UPDATE passwords 
		SET title = ?, username = ?, password = ?, url = ?, notes = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ? AND user_id = ?`,
		req.Title, req.Username, encryptedPassword, req.URL, req.Notes, passwordID, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password updated"})
}

func deletePasswordHandler(c *gin.Context) {
	userID, _ := c.Get("userID")
	passwordID := c.Param("id")

	_, err := db.Exec("DELETE FROM passwords WHERE id = ? AND user_id = ?", passwordID, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete password"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password deleted"})
}

// Export/Import handlers
func exportHandler(c *gin.Context) {
	userID, _ := c.Get("userID")
	format := c.Query("format")
	if format == "" {
		format = "csv"
	}

	rows, err := db.Query(`
		SELECT title, username, password, url, notes
		FROM passwords 
		WHERE user_id = ?`, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to export passwords"})
		return
	}
	defer rows.Close()

	var passwords []PasswordEntry
	for rows.Next() {
		var p PasswordEntry
		var encryptedPassword string
		err := rows.Scan(&p.Title, &p.Username, &encryptedPassword, &p.URL, &p.Notes)
		if err != nil {
			continue
		}

		// Decrypt password for export
		masterKey := userID.(string) + "_master"
		decryptedPassword, err := decryptPassword(encryptedPassword, masterKey)
		if err == nil {
			p.Password = decryptedPassword
		} else {
			p.Password = ""
		}

		passwords = append(passwords, p)
	}

	switch format {
	case "json":
		c.Header("Content-Type", "application/json")
		c.Header("Content-Disposition", `attachment; filename="passwords.json"`)
		json.NewEncoder(c.Writer).Encode(passwords)
	case "chrome":
		chromeFormat := map[string]interface{}{
			"folders": []interface{}{},
			"items": passwords,
		}
		c.Header("Content-Type", "application/json")
		c.Header("Content-Disposition", `attachment; filename="passwords_chrome.json"`)
		json.NewEncoder(c.Writer).Encode(chromeFormat)
	default: // CSV
		c.Header("Content-Type", "text/csv")
		c.Header("Content-Disposition", `attachment; filename="passwords.csv"`)
		
		c.Writer.Write([]byte("title,username,password,url,notes\n"))
		for _, p := range passwords {
			line := fmt.Sprintf("%q,%q,%q,%q,%q\n",
				strings.ReplaceAll(p.Title, "\"", "\"\""),
				strings.ReplaceAll(p.Username, "\"", "\"\""),
				strings.ReplaceAll(p.Password, "\"", "\"\""),
				strings.ReplaceAll(p.URL, "\"", "\"\""),
				strings.ReplaceAll(p.Notes, "\"", "\"\""),
			)
			c.Writer.Write([]byte(line))
		}
	}
}

func importHandler(c *gin.Context) {
	userID, _ := c.Get("userID")
	format := c.Query("format")
	if format == "" {
		format = "csv"
	}

	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No file provided"})
		return
	}

	f, err := file.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to open file"})
		return
	}
	defer f.Close()

	content, err := io.ReadAll(f)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read file"})
		return
	}

	// Parse based on format
	var passwords []PasswordRequest
	switch format {
	case "json":
		if err := json.Unmarshal(content, &passwords); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON format"})
			return
		}
	case "chrome":
		var chromeFormat struct {
			Items []PasswordRequest `json:"items"`
		}
		if err := json.Unmarshal(content, &chromeFormat); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Chrome format"})
			return
		}
		passwords = chromeFormat.Items
	default: // CSV
		lines := strings.Split(string(content), "\n")
		if len(lines) < 2 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid CSV format"})
			return
		}


		for i := 1; i < len(lines); i++ {
			if lines[i] == "" {
				continue
			}

			fields := parseCSVLine(lines[i])
			if len(fields) < 3 { // Need at least title, username, password
				continue
			}

			p := PasswordRequest{
				Title:    fields[0],
				Username: fields[1],
				Password: fields[2],
			}

			if len(fields) > 3 {
				p.URL = fields[3]
			}
			if len(fields) > 4 {
				p.Notes = fields[4]
			}

			passwords = append(passwords, p)
		}
	}

	// Import passwords
	masterKey := userID.(string) + "_master"
	successCount := 0

	for _, p := range passwords {
		if p.Title == "" || p.Username == "" || p.Password == "" {
			continue
		}

		encryptedPassword, err := encryptPassword(p.Password, masterKey)
		if err != nil {
			continue
		}

		_, err = db.Exec(`
			INSERT INTO passwords (id, user_id, title, username, password, url, notes)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
			uuid.NewV4().String(), userID, p.Title, p.Username, encryptedPassword, p.URL, p.Notes,
		)

		if err == nil {
			successCount++
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf("Imported %d of %d passwords", successCount, len(passwords)),
	})
}

func parseCSVLine(line string) []string {
	var fields []string
	var currentField strings.Builder
	inQuotes := false

	for i := 0; i < len(line); i++ {
		ch := line[i]

		if ch == '"' {
			if inQuotes && i+1 < len(line) && line[i+1] == '"' {
				currentField.WriteByte('"')
				i++
			} else {
				inQuotes = !inQuotes
			}
		} else if ch == ',' && !inQuotes {
			fields = append(fields, currentField.String())
			currentField.Reset()
		} else {
			currentField.WriteByte(ch)
		}
	}

	fields = append(fields, currentField.String())
	return fields
}

// Static file serving
func serveFrontend(c *gin.Context) {
	path := c.Request.URL.Path
	if path == "/" {
		c.File("./frontend/index.html")
	} else if strings.HasPrefix(path, "/api/") {
		c.Next()
	} else {
		filePath := "./frontend" + path
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			c.File("./frontend/index.html")
		} else {
			c.File(filePath)
		}
	}
}

func main() {
	// Initialize database
	if err := initDB(); err != nil {
		log.Fatal("Failed to initialize database:", err)
	}
	defer db.Close()

	// Create frontend directory if not exists
	os.MkdirAll("./frontend", 0755)

	// Create basic index.html
	indexHTML := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecurePass - Password Manager</title>
    <link rel="stylesheet" href="/styles.css">
    <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🔐</text></svg>">
</head>
<body>
    <div id="app"></div>
    <script src="/app.js"></script>
</body>
</html>`
	os.WriteFile("./frontend/index.html", []byte(indexHTML), 0644)

	// Setup Gin router
	r := gin.Default()

	// CORS configuration
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	// Serve frontend files
	r.StaticFS("/static", http.Dir("./frontend"))
	r.GET("/", serveFrontend)
	r.GET("/styles.css", serveFrontend)
	r.GET("/app.js", serveFrontend)

	// API routes
	api := r.Group("/api")
	{
		// Auth routes
		api.POST("/auth/register", registerHandler)
		api.POST("/auth/login", loginHandler)
		api.POST("/auth/logout", logoutHandler)

		// Password routes (protected)
		passwordRoutes := api.Group("/passwords")
		passwordRoutes.Use(authMiddleware())
		{
			passwordRoutes.GET("", getPasswordsHandler)
			passwordRoutes.POST("", createPasswordHandler)
			passwordRoutes.GET("/:id", getPasswordHandler)
			passwordRoutes.PUT("/:id", updatePasswordHandler)
			passwordRoutes.DELETE("/:id", deletePasswordHandler)
		}

		// Export/Import routes
		exportRoutes := api.Group("/export")
		exportRoutes.Use(authMiddleware())
		{
			exportRoutes.GET("", exportHandler)
			exportRoutes.POST("/import", importHandler)
		}
	}

	// Health check
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy"})
	})

	// Start server
	fmt.Println("SecurePass Password Manager starting on :18080")
	fmt.Println("Open http://localhost:18080 in your browser")
	
	if err := r.Run(":18080"); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}