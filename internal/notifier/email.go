package notifier

import (
	"fmt"
	"net/smtp"
	"strings"
)

type EmailConfig struct {
	SMTPServer string
	SMTPPort   string
	Username   string
	Password   string
	From       string
	To         string
	Subject    string
}

func NewEmailNotifier() *EmailConfig {
	return &EmailConfig{
		SMTPPort: "587",
		Subject:  "PolkitGuard Security Alert",
	}
}

func (e *EmailConfig) Notify(summary Summary) error {
	if summary.Total == 0 {
		return nil
	}

	msg := fmt.Sprintf("From: %s\r\n", e.From)
	msg += fmt.Sprintf("To: %s\r\n", e.To)
	msg += fmt.Sprintf("Subject: %s\r\n", e.Subject)
	msg += "\r\n"
	msg += fmt.Sprintf("PolkitGuard Security Scan Report\r\n")
	msg += fmt.Sprintf("==========================\r\n\r\n")
	msg += fmt.Sprintf("Total Issues: %d\r\n", summary.Total)
	msg += fmt.Sprintf("Critical: %d\r\n", summary.Critical)
	msg += fmt.Sprintf("High: %d\r\n", summary.High)
	msg += fmt.Sprintf("Medium: %d\r\n", summary.Medium)
	msg += fmt.Sprintf("Low: %d\r\n\r\n", summary.Low)

	if summary.Critical > 0 || summary.High > 0 {
		msg += "ACTION REQUIRED: Please review critical and high severity issues immediately.\r\n"
	}

	addr := e.SMTPServer
	if e.SMTPPort != "" {
		addr += ":" + e.SMTPPort
	}

	auth := smtp.PlainAuth("", e.Username, e.Password, e.SMTPServer)
	err := smtp.SendMail(addr, auth, e.From, []string{e.To}, []byte(msg))
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}

func (e *EmailConfig) Validate() error {
	if e.To == "" {
		return fmt.Errorf("email 'to' is required")
	}
	if e.SMTPServer == "" {
		return fmt.Errorf("SMTPServer is required")
	}
	return nil
}

type EmailNotifier struct {
	SMTPServer string
	SMTPPort   string
	Username   string
	Password   string
	From       string
	To         []string
	Subject    string
}

func NewEmailNotifierWithRecipients() *EmailNotifier {
	return &EmailNotifier{
		SMTPPort: "587",
		Subject:  "PolkitGuard Security Alert",
	}
}

func (n *EmailNotifier) AddRecipient(email string) {
	n.To = append(n.To, email)
}

func (n *EmailNotifier) Send(summary Summary) error {
	if len(n.To) == 0 {
		return fmt.Errorf("no recipients configured")
	}

	subject := n.Subject
	if summary.Critical > 0 {
		subject = "[CRITICAL] " + subject
	} else if summary.High > 0 {
		subject = "[HIGH] " + subject
	}

	body := fmt.Sprintf("PolkitGuard Scan Report\n"+
		"Total: %d | Critical: %d | High: %d | Medium: %d | Low: %d\n\n",
		summary.Total, summary.Critical, summary.High, summary.Medium, summary.Low)

	msg := "From: " + n.From + "\r\n"
	msg += "To: " + strings.Join(n.To, ",") + "\r\n"
	msg += "Subject: " + subject + "\r\n"
	msg += "\r\n" + body

	addr := n.SMTPServer
	if n.SMTPPort != "" {
		addr += ":" + n.SMTPPort
	}

	auth := smtp.PlainAuth("", n.Username, n.Password, n.SMTPServer)
	return smtp.SendMail(addr, auth, n.From, n.To, []byte(msg))
}
