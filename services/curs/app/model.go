package main
type User struct {
	Id         int
	Login	   string
	Password   string
	Role	   string
	TicketNumber string `json:"ticket_number"`
}
type Ticket struct {
    Id int `json:"id"`
	UserId int `json:"user_id"`
	TicketNumber string `json:"ticket_number"`
}