package main
import (
	"github.com/gin-gonic/gin"
	"github.com/gin-contrib/sessions"
    "net/http"
)
func authRequired(c *gin.Context) {
    session := sessions.Default(c)
    userId := session.Get("user_id")
    userRole := session.Get("user_role")


	if userId == nil || userRole == nil {
        c.Redirect(http.StatusSeeOther, "/user/login")
        c.Abort()
        return
    }
    c.Next()
}
