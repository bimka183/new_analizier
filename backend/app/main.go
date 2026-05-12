package main

import (
	"analizier/backend/src/detector"
	"analizier/backend/src/models"
	"analizier/backend/src/repository"
	"analizier/backend/src/service"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// ------------------------------------------------------------
// Client
// ------------------------------------------------------------

type Client struct {
	Conn *websocket.Conn
	Send chan models.Traffic
}

// ------------------------------------------------------------
// App
// ------------------------------------------------------------

type App struct {
	Router         *gin.Engine
	DB             *gorm.DB
	Clients        map[*Client]bool
	Broadcast      chan models.Traffic
	Upgrader       websocket.Upgrader
	TrafficService *service.TrafficService
	TrafficRepo    repository.TrafficRepository

	progressMu sync.Mutex
	progressCh map[uint]chan models.ProgressEvent
}

func NewApp(db *gorm.DB) *App {
	router := gin.Default()
	router.MaxMultipartMemory = 512 << 20

	repo := repository.NewPostgresTrafficRepo(db)

	// Инициализация детекторов
	_, internalNet, _ := net.ParseCIDR("59.166.0.0/16")
	detectors := []detector.Detector{
		&detector.DDoSDetector{},
		detector.NewWormDetector(200, 100_000, internalNet),
		detector.NewAdaptiveOverloadDetector(10, 2.7),
		detector.NewVirusDetector([]string{}),
	}

	broadcast := make(chan models.Traffic)

	// FlowDetector'ы (пока пустой список — P2MP / FlowSwitching подключаются здесь)
	var flowDetectors []detector.FlowDetector

	trafficService := service.NewTrafficService(repo, detectors, flowDetectors, broadcast)

	return &App{
		Router:    router,
		DB:        db,
		Clients:   make(map[*Client]bool),
		Broadcast: broadcast,
		Upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
		TrafficService: trafficService,
		TrafficRepo:    repo,
		progressCh:     make(map[uint]chan models.ProgressEvent),
	}
}

func (a *App) SetupRouter() {
	a.Router.Use(a.corsMiddleware())

	api := a.Router.Group("/api")
	{
		api.POST("/traffic", a.handlePostTraffic)
		api.GET("/traffic", a.handleGetTraffic)
		api.GET("/traffic/:id", a.handleGetTrafficByID)
		api.POST("/upload", a.handleUpload)
		api.GET("/uploads", a.handleGetUploads)
		api.GET("/uploads/:id", a.handleGetUploadByID)
		api.DELETE("/uploads/:id", a.handleDeleteUpload)
		api.GET("/uploads/:id/progress", a.handleGetUploadProgress)
		api.POST("/login", a.handleLogin)

		// Администраторские эндпоинты
		admin := api.Group("/admin")
		admin.Use(a.authMiddleware("admin"))
		{
			admin.DELETE("/traffic", a.handleDeleteTraffic)
			admin.POST("/reset", a.handleReset)
		}
	}
	a.Router.GET("/ws", a.handleWebSocket)
}

func (a *App) corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(200)
			return
		}
		c.Next()
	}
}

// hashPassword — простое хеширование пароля (SHA-256)
func hashPassword(password string) string {
	h := sha256.New()
	h.Write([]byte(password))
	return hex.EncodeToString(h.Sum(nil))
}

// authMiddleware — простая middleware для проверки роли по заголовку Authorization
// Формат: Authorization: username:password
func (a *App) authMiddleware(requiredRole string) gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		if auth == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization required"})
			c.Abort()
			return
		}

		// Парсим "username:password"
		var username, password string
		for i, ch := range auth {
			if ch == ':' {
				username = auth[:i]
				password = auth[i+1:]
				break
			}
		}
		if username == "" || password == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization format. Use username:password"})
			c.Abort()
			return
		}

		user, err := a.TrafficRepo.GetUserByUsername(username)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
			c.Abort()
			return
		}

		if user.Password != hashPassword(password) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid password"})
			c.Abort()
			return
		}

		if requiredRole != "" && user.Role != requiredRole {
			c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions. Required role: " + requiredRole})
			c.Abort()
			return
		}

		c.Set("user", user)
		c.Next()
	}
}

// --- Handlers ---

func (a *App) handleUpload(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	path := "files/" + file.Filename
	if err = c.SaveUploadedFile(file, path); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	fmt.Printf("Uploading file: %s\n", path)

	fileUpload := &models.FileUpload{
		Filename: file.Filename,
		Status:   "processing",
		Summary:  "{}",
	}
	if err := a.TrafficRepo.CreateFileUpload(fileUpload); err != nil {
		c.JSON(500, gin.H{"error": "Failed to create upload record: " + err.Error()})
		return
	}

	progressCh := make(chan models.ProgressEvent, 64)
	a.progressMu.Lock()
	a.progressCh[fileUpload.ID] = progressCh
	a.progressMu.Unlock()

	c.JSON(200, gin.H{"status": "queued", "upload_id": fileUpload.ID})

	go func(uploadID uint, filename string) {
		defer func() {
			a.progressMu.Lock()
			delete(a.progressCh, uploadID)
			a.progressMu.Unlock()
			close(progressCh)
		}()

		results, procErr := a.TrafficService.PipelineWithProgress(filename, progressCh, uploadID)
		if procErr != nil {
			fmt.Printf("Processing error for upload %d: %v\n", uploadID, procErr)
			upload, _ := a.TrafficRepo.GetFileUploadByID(uploadID)
			if upload != nil {
				upload.Status = "error"
				upload.Error = procErr.Error()
				a.TrafficRepo.UpdateFileUpload(upload)
			}
			sendProgress(progressCh, "error", 0)
			return
		}

		fmt.Printf("File parsed, analyzed and saved. Upload %d, total results: %d\n", uploadID, len(results))

		summary := buildUploadFlowSummary(results)
		summaryJSON, _ := json.Marshal(summary)

		upload, _ := a.TrafficRepo.GetFileUploadByID(uploadID)
		if upload != nil {
			upload.Status = "completed"
			upload.FlowCount = len(results)
			upload.Summary = string(summaryJSON)
			a.TrafficRepo.UpdateFileUpload(upload)
		}

		sendProgress(progressCh, "done", 100)
	}(fileUpload.ID, path)
}

func sendProgress(ch chan<- models.ProgressEvent, phase string, progress int) {
	if ch == nil {
		return
	}
	select {
	case ch <- models.ProgressEvent{Phase: phase, Progress: progress}:
	default:
	}
}

func (a *App) handleGetUploadProgress(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid id parameter"})
		return
	}

	a.progressMu.Lock()
	ch, ok := a.progressCh[uint(id)]
	a.progressMu.Unlock()

	if !ok {
		upload, dbErr := a.TrafficRepo.GetFileUploadByID(uint(id))
		if dbErr != nil {
			c.JSON(404, gin.H{"error": "upload not found"})
			return
		}
		c.Header("Content-Type", "text/event-stream")
		c.Header("Cache-Control", "no-cache")
		c.Header("Connection", "keep-alive")
		if upload.Status == "completed" {
			fmt.Fprintf(c.Writer, "data: %s\n\n", mustJSON(models.ProgressEvent{Phase: "done", Progress: 100}))
		} else if upload.Status == "error" {
			fmt.Fprintf(c.Writer, "data: %s\n\n", mustJSON(models.ProgressEvent{Phase: "error", Progress: 0}))
		}
		c.Writer.Flush()
		return
	}

	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Writer.Flush()

	clientGone := c.Request.Context().Done()
	for {
		select {
		case <-clientGone:
			return
		case evt, open := <-ch:
			if !open {
				return
			}
			fmt.Fprintf(c.Writer, "data: %s\n\n", mustJSON(evt))
			c.Writer.Flush()
			if evt.Phase == "done" || evt.Phase == "error" {
				return
			}
		}
	}
}

func mustJSON(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func (a *App) handleGetUploads(c *gin.Context) {
	uploads, err := a.TrafficRepo.GetFileUploads()
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"data": uploads})
}

func (a *App) handleGetUploadByID(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid id parameter"})
		return
	}
	upload, err := a.TrafficRepo.GetFileUploadByID(uint(id))
	if err != nil {
		c.JSON(404, gin.H{"error": "upload not found"})
		return
	}
	c.JSON(200, gin.H{
		"id":          upload.ID,
		"filename":    upload.Filename,
		"uploaded_at": upload.UploadAt,
		"flow_count":  upload.FlowCount,
		"status":      upload.Status,
		"error":       upload.Error,
		"summary":     upload.Summary,
	})
}

func (a *App) handleDeleteUpload(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid id parameter"})
		return
	}
	if err := a.TrafficRepo.DeleteFileUpload(uint(id)); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"status": "deleted"})
}

func (a *App) handlePostTraffic(c *gin.Context) {
	var traffic models.Traffic
	if err := c.ShouldBindJSON(&traffic); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	enrichTrafficFlowStats(&traffic)

	// Автоматический вывод протокола, если он не передан (например, из старых тестовых скриптов)
	if traffic.Protocol == "" {
		if traffic.Flags != "" || traffic.SourcePort != "" || traffic.DestinationPort != "" {
			traffic.Protocol = "TCP"
		} else {
			traffic.Protocol = "Other"
		}
	}

	// Если передана аномалия "None", то удаляем ее из списка, чтобы не писать в таблицу anomalies
	var filteredAnomalies []models.Anomaly
	for _, an := range traffic.Anomalies {
		if an.AnomalyType != "None" && an.AnomalyType != "" {
			filteredAnomalies = append(filteredAnomalies, an)
		}
	}
	traffic.Anomalies = filteredAnomalies

	a.DB.Create(&traffic)
	a.Broadcast <- traffic
	c.JSON(http.StatusOK, traffic)
}

func (a *App) handleGetTraffic(c *gin.Context) {
	page := c.DefaultQuery("page", "1")
	limit := c.DefaultQuery("limit", "20")

	var pageInt, limitInt int
	fmt.Sscanf(page, "%d", &pageInt)
	fmt.Sscanf(limit, "%d", &limitInt)
	if pageInt < 1 {
		pageInt = 1
	}
	if limitInt < 1 {
		limitInt = 20
	}
	offset := (pageInt - 1) * limitInt

	uploadIDStr := c.DefaultQuery("upload_id", "0")
	var uploadID uint
	if v, e := strconv.ParseUint(uploadIDStr, 10, 64); e == nil {
		uploadID = uint(v)
	}

	filter := models.TrafficFilter{
		SourceIP:      c.DefaultQuery("source_ip", ""),
		DestinationIP: c.DefaultQuery("destination_ip", ""),
		Port:          c.DefaultQuery("port", ""),
		AnomalyType:   c.DefaultQuery("anomaly", ""),
		Protocol:      c.DefaultQuery("protocol", ""),
		Flags:         c.DefaultQuery("flags", ""),
		UploadID:      uploadID,
	}

	traffic, err := a.TrafficRepo.GetTrafficWithFilter(limitInt, offset, filter)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	total, err := a.TrafficRepo.CountTraffic(filter)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":  traffic,
		"total": total,
	})
}

func (a *App) handleGetTrafficByID(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id parameter"})
		return
	}

	traffic, err := a.TrafficRepo.GetTrafficByID(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "traffic record not found"})
		return
	}

	c.JSON(http.StatusOK, traffic)
}

// handleDeleteTraffic — очистка всех данных из БД (только для администратора)
func (a *App) handleDeleteTraffic(c *gin.Context) {
	err := a.TrafficRepo.DeleteAllTraffic()
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"status": "all traffic data deleted"})
}

// handleReset — откат до базовых настроек (только для администратора)
func (a *App) handleReset(c *gin.Context) {
	err := a.TrafficRepo.ResetDatabase()
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"status": "database reset to default state"})
}

// handleLogin — аутентификация пользователя
func (a *App) handleLogin(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	user, err := a.TrafficRepo.GetUserByUsername(req.Username)
	if err != nil {
		c.JSON(401, gin.H{"error": "Invalid username or password"})
		return
	}

	if user.Password != hashPassword(req.Password) {
		c.JSON(401, gin.H{"error": "Invalid username or password"})
		return
	}

	c.JSON(200, gin.H{
		"status":   "ok",
		"username": user.Username,
		"role":     user.Role,
	})
}

func (a *App) handleWebSocket(c *gin.Context) {
	conn, err := a.Upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		return
	}

	client := &Client{Conn: conn, Send: make(chan models.Traffic, 10)}
	a.Clients[client] = true
	fmt.Println("WS client connected")

	go a.writePump(client)
	go a.readPump(client)
}

func (a *App) writePump(client *Client) {
	for msg := range client.Send {
		if err := client.Conn.WriteJSON(msg); err != nil {
			break
		}
	}
	client.Conn.Close()
}

func (a *App) readPump(client *Client) {
	defer func() {
		delete(a.Clients, client)
		client.Conn.Close()
		fmt.Println("WS client disconnected")
	}()
	for {
		if _, _, err := client.Conn.NextReader(); err != nil {
			break
		}
	}
}

func (a *App) runBroadcast() {
	for traffic := range a.Broadcast {
		for client := range a.Clients {
			select {
			case client.Send <- traffic:
			default:
				close(client.Send)
				delete(a.Clients, client)
			}
		}
	}
}

// seedDefaultAdmin создаёт администратора по умолчанию, если его нет
func seedDefaultAdmin(repo repository.TrafficRepository) {
	_, err := repo.GetUserByUsername("admin")
	if err != nil {
		// Пользователь не найден, создаём
		admin := &models.User{
			Username: "admin",
			Password: hashPassword("admin"),
			Role:     "admin",
		}
		repo.CreateUser(admin)
		fmt.Println("Default admin user created (admin/admin)")
	}

	// Создаём обычного пользователя
	_, err = repo.GetUserByUsername("user")
	if err != nil {
		user := &models.User{
			Username: "user",
			Password: hashPassword("user"),
			Role:     "user",
		}
		repo.CreateUser(user)
		fmt.Println("Default user created (user/user)")
	}
}

// ------------------------------------------------------------
// Main
// ------------------------------------------------------------

func main() {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		dsn = "host=localhost user=postgres password=postgres dbname=traffic port=5432 sslmode=disable TimeZone=UTC"
	}

	var db *gorm.DB
	var err error

	// Повторяем попытки подключения (для docker-compose, когда postgres ещё не запущен полностью)
	for i := 0; i < 15; i++ {
		db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
		if err == nil {
			break
		}
		fmt.Printf("Failed to connect to database. Retrying in 2 seconds... (%d/15)\n", i+1)
		time.Sleep(2 * time.Second)
	}

	if err != nil {
		panic(fmt.Errorf("could not connect to database after retries: %v", err))
	}

	db.AutoMigrate(&models.Traffic{}, &models.Anomaly{}, &models.User{}, &models.FileUpload{})

	if db.Migrator().HasColumn(&models.FileUpload{}, "results") {
		db.Migrator().DropColumn(&models.FileUpload{}, "results")
	}

	app := NewApp(db)

	// Создаём пользователей по умолчанию
	seedDefaultAdmin(app.TrafficRepo)

	app.SetupRouter()

	go app.runBroadcast()

	fmt.Println("Server starting on 0.0.0.0:8080")
	app.Router.Run("0.0.0.0:8080")
}
