package main

import (
	"log"
	"github.com/gin-gonic/gin"
	"database/sql"
	"html/template"
	"github.com/gin-contrib/sessions"
    "github.com/gin-contrib/sessions/cookie"
)
var (
	router *gin.Engine
	db     *sql.DB
	err error
)
func initRoutes() {
	router = gin.Default()

	store := cookie.NewStore([]byte("your-secret-key"))
    store.Options(sessions.Options{
        Path:     "/",        // Доступно для всех путей
        Domain:   "",         // Пустой = работает на IP и localhost
        MaxAge:   3600 * 24,  // 24 часа, подстройте под нужды
        Secure:   false,      // false для HTTP (для разработки), true для HTTPS в проде
        HttpOnly: true,       // Защита от XSS
    })
    router.Use(sessions.Sessions("mysession", store))

	router.SetFuncMap(template.FuncMap{
        "safeHTML": func(str string) template.HTML {
            return template.HTML(str)
        },
    })
    router.LoadHTMLGlob("templates/*.html")
	router.Static("/static", "./templates/static")
	router.GET("/", showMainPage)

	router.GET("/dashboard", authRequired, func(c *gin.Context) {
        showDashboardPage(c, db)
    })

	userRoutes := router.Group("/user")
	{
		userRoutes.GET("/register", showRegisterPage)
		userRoutes.POST("/register", insertUser)
		userRoutes.GET("/login", showLoginPage)
		userRoutes.POST("/login", func (c *gin.Context) {
			loginUser(c, db)
		})
		
	}
	userRoutes.GET("/logout", logoutUser)
	
}
func main() {

	db, err = InitDB()
	if err != nil {
		log.Fatalf("Ошибка при инициализации БД: %v", err)
		return
	}
	defer db.Close()

	initRoutes()
	log.Fatal(router.Run(":8083"))
}