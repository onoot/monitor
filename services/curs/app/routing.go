package main

import (
	"fmt"
	"net/http"
    "database/sql"
	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gin-contrib/sessions"
	"math/rand"
	"time"
)

func renderMessage(c *gin.Context, template string, status int, messageType string, message string, data gin.H) {
    if data == nil {
        data = gin.H{}
    }

    var messageHTML string
    if messageType == "error" {
        messageHTML = fmt.Sprintf("<div class=\"error-message\">%s</div>", message)
    } else if messageType == "success" {
        messageHTML = fmt.Sprintf("<div class=\"success-message\">%s</div>", message)
    }
    data["message"] = messageHTML //передаем в шаблон сформированное сообщение, а не отдельное поле error или message
    c.HTML(status, template, data)
}


func showMainPage(g *gin.Context) {
	session := sessions.Default(g)
    userId := session.Get("user_id")
    userRole := session.Get("user_role")
	
    data := gin.H{"user_id":userId, "user_role": userRole}

	if userRole == "admin"{
		users, err := getAllUsers(db)
		if err != nil{
            g.HTML(http.StatusInternalServerError, "index.html", gin.H{"error": err.Error()})
            return
        }
        data["users"] = users
	}
    g.HTML(http.StatusOK, "index.html", data)
}

func showLoginPage(c *gin.Context) {
	c.HTML(http.StatusOK, "login.html", gin.H{})
}

func showRegisterPage(c *gin.Context) {
	c.HTML(http.StatusOK, "register.html", gin.H{})
}
func showDashboardPage(c *gin.Context, db *sql.DB) {
    session := sessions.Default(c)
    userId := session.Get("user_id")
 
	userIdInt, ok := userId.(int)
    if !ok {
        renderMessage(c, "index.html", http.StatusInternalServerError, "error", "Неверный тип user_id", gin.H{})
        return
    }
	userRole := session.Get("user_role").(string)

	var ticketNumber string
	var err error
	
	ticketNumber, err = getOrCreateTicket(db, userIdInt)
	if err != nil {
		renderMessage(c, "index.html", http.StatusInternalServerError, "error", fmt.Sprintf("Ошибка при получении или создании билета: %v", err), gin.H{"user_id":userId, "user_role": userRole, "ticket_number": ""})
		return
	}

	c.HTML(http.StatusOK, "dashboard.html", gin.H{"user_id":userId, "user_role": userRole, "ticket_number": ticketNumber})
}
func insertUser(c *gin.Context) {
	login := c.PostForm("login")
	password := c.PostForm("password")


	var existingUser User
	err := db.QueryRow("SELECT login FROM users WHERE login = ?", login).Scan(&existingUser.Login)

	if err == nil {
        renderMessage(c, "register.html", http.StatusConflict, "error", fmt.Sprintf("Логин '%s' уже существует.", login), nil)
		return
	} else if err != sql.ErrNoRows {
        renderMessage(c, "register.html", http.StatusInternalServerError, "error", fmt.Sprintf("Ошибка проверки существования пользователя: %v", err), nil)
		return
	}

    stmt, err := db.Prepare("INSERT INTO users (login, password) VALUES (?, ?)")
	if err != nil {
        renderMessage(c, "register.html", http.StatusInternalServerError, "error", fmt.Sprintf("Ошибка при подготовке запроса: %v", err), nil)
		return
	}
	defer stmt.Close()

	result, err := stmt.Exec(login, password)
	if err != nil {
        renderMessage(c, "register.html", http.StatusInternalServerError, "error", fmt.Sprintf("Ошибка при выполнении запроса: %v", err), nil)
		return
	}

    affectedRows, err := result.RowsAffected()
	if err != nil {
		renderMessage(c, "register.html", http.StatusInternalServerError, "error", fmt.Sprintf("Ошибка получения количества измененных строк: %v", err), nil)
		return
	}

	if affectedRows == 0 {
        renderMessage(c, "register.html", http.StatusInternalServerError, "error", "Ошибка добавления пользователя в базу данных. Ничего не добавлено.", nil)
		return
	}

	renderMessage(c, "register.html", http.StatusOK, "success", "Пользователь успешно создан", nil)
}

func loginUser(c *gin.Context, db *sql.DB) {
    login := c.PostForm("login")
	password := c.PostForm("password")
	
	var user User
	query := fmt.Sprintf("SELECT id, login, password, role FROM users WHERE login = '%s' AND password = '%s'", login, password)
	err := db.QueryRow(query).Scan(&user.Id, &user.Login, &user.Password, &user.Role)
	if err != nil {
		if err == sql.ErrNoRows {
            renderMessage(c, "login.html", http.StatusUnauthorized, "error", "Неверный логин или пароль", gin.H{"login":login, "password":password})
		} else {
            renderMessage(c, "login.html", http.StatusInternalServerError, "error", fmt.Sprintf("Ошибка при выполнении запроса к БД: %v", err), gin.H{"login":login, "password":password})
		}
		return
	}

    session := sessions.Default(c)
    session.Set("user_id", user.Id)
    session.Set("user_role", user.Role)
    err = session.Save()
    if err != nil {
        renderMessage(c, "login.html", http.StatusInternalServerError, "error", fmt.Sprintf("Ошибка сохранения сессии: %v", err), gin.H{"login":login, "password":password})
        return
    }

	c.Redirect(http.StatusSeeOther, "/dashboard")
}
func logoutUser(c *gin.Context) {
    session := sessions.Default(c)
    session.Clear() 
    session.Save()
    c.Redirect(http.StatusSeeOther, "/") 
}

func getAllUsers(db *sql.DB) ([]User, error) {
    rows, err := db.Query("SELECT u.id, u.login, u.password, u.role, t.ticket_number FROM users u LEFT JOIN tickets t ON u.id = t.user_id")
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var users []User
    for rows.Next() {
        var user User
        var ticketNumber sql.NullString
		if err := rows.Scan(&user.Id, &user.Login, &user.Password, &user.Role, &ticketNumber); err != nil {
            return nil, err
        }
        user.TicketNumber = ticketNumber.String
		users = append(users, user)
    }

    if err := rows.Err(); err != nil {
        return nil, err
    }

    return users, nil
}

func getOrCreateTicket(db *sql.DB, userId int) (string, error) {
	var ticketNumber string
    err := db.QueryRow("SELECT ticket_number FROM tickets WHERE user_id = ?", userId).Scan(&ticketNumber)
	if err == sql.ErrNoRows{
		rand.Seed(time.Now().UnixNano())
		ticketNumber = fmt.Sprintf("%010d", rand.Intn(10000000000))

        _, err = db.Exec("INSERT INTO tickets (user_id, ticket_number) VALUES (?, ?)", userId, ticketNumber)
        if err != nil {
            return "", fmt.Errorf("ошибка при создании нового билета: %w", err)
        }
		return ticketNumber, nil
	}

	if err != nil {
        return "", fmt.Errorf("ошибка при получении существующего билета: %w", err)
    }
	
    return ticketNumber, nil
}