package main

import (
	"net/smtp"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"strings"

	"github.com/domainr/whois"
	"github.com/inimei/backup/log"
	"github.com/likexian/whois-parser-go"
)

const (
	gUser    = ""
	gPWD     = ""
	gServer  = "mail.kmail.com:25"
	gTo      = ""
	gSubject = "Check Domain Status"
)

func cdCWD() error {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		return err
	}
	err = os.Chdir(dir)
	if err != nil {
		return err
	}
	return nil
}

func main() {

	log.SetLevel(log.LevelAll)

	if err := cdCWD(); err != nil {
		log.Error(err.Error())
	}

	log.SetLogFile("./check_domain_status.log")
	log.SetLevel(log.LevelAll)
	defer log.Close()

	interrupSig := make(chan os.Signal)
	signal.Notify(interrupSig, os.Interrupt)
	killSig := make(chan os.Signal)
	signal.Notify(killSig, os.Kill)

	//没个小时检查一次
forever:
	for {
		select {
		case <-interrupSig:
			break forever
		case <-killSig:
			break forever
		case <-time.After(time.Hour):
			go checkStatus()
		}
	}
}

func checkStatus() {
	log.Info("start check ddns.site")
	query := "ddns.site"
	request, err := whois.NewRequest(query)
	response, err := whois.DefaultClient.Fetch(request)
	if err != nil {
		log.Error(err.Error())
		err := sendToMail(gUser, gPWD, gServer, gTo, gSubject, "FETCH whois failed\r\n"+err.Error())
		if err != nil {
			log.Error(err.Error())
		}
		return
	}

	result, err := whois_parser.Parser(string(response.Body))
	if err != nil {
		log.Error(err.Error())
		err := sendToMail(gUser, gPWD, gServer, gTo, gSubject, "PARSER whois failed\r\n"+err.Error())
		if err != nil {
			log.Error(err.Error())
		}
		return
	}

	st := result.Registrar.DomainStatus
	statuses := strings.Split(st, ",")
	if len(statuses) == 0 {
		log.Error("get status failed")
		err := sendToMail(gUser, gPWD, gServer, gTo, gSubject, "get status failed\r\n"+st)
		if err != nil {
			log.Error(err.Error())
		}
		return
	}

	statuses = strings.Split(statuses[0], " ")
	if len(statuses) == 0 {
		log.Error("get status failed")
		err := sendToMail(gUser, gPWD, gServer, gTo, gSubject, "get status failed\r\n"+statuses[0])
		if err != nil {
			log.Error(err.Error())
		}
		return
	}

	if statuses[0] != "pendingdelete" {
		log.Error("status changed!")
		msg := "status CHANGED!!!!!\r\n\t\t" + statuses[0] + "\r\n"
		err := sendToMail(gUser, gPWD, gServer, gTo, gSubject, msg+msg+msg)
		if err != nil {
			log.Error(err.Error())
		}
		return
	}

	log.Info("end check ddns.site")
}

func sendToMail(user, password, host, to, subject, body string) error {
	hp := strings.Split(host, ":")
	auth := smtp.PlainAuth("", user, password, hp[0])
	contentType := "Content-Type: text/plain" + "; charset=UTF-8"

	msg := []byte("To: " + to + "\r\nFrom: " + user + ">\r\nSubject: " + subject + "\r\n" + contentType + "\r\n\r\n" + body)
	sendTo := strings.Split(to, ";")
	return smtp.SendMail(host, auth, user, sendTo, msg)
}
