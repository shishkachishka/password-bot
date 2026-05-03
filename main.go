package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
)

// СТРУКТУРЫ

type EncryptedData struct {
	Ciphertext string `json:"ciphertext"`
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
}

type PasswordEntry struct {
	ID        string `json:"id"`
	Note      string `json:"note"`
	Data      string `json:"data"`
	CreatedAt string `json:"created_at"`
}

type Storage struct {
	MasterHash string          `json:"master_hash"`
	MasterSalt string          `json:"master_salt"`
	Passwords  []PasswordEntry `json:"passwords"`
}

type UserSession struct {
	ChatID     int64
	MasterKey  []byte
	IsLoggedIn bool
	storage    *Storage
}

var (
	sessions      = make(map[int64]*UserSession)
	bot           *tgbotapi.BotAPI
	backupChannel int64 = -1003958712976

	// яндекс диск
	webdavUser = os.Getenv("WEBDAV_USER") // ← логин берется из Render
	webdavPass = os.Getenv("WEBDAV_PASS") // ← пароль берется из Render
	webdavURL  = "https://webdav.yandex.ru"
)

//ШИФРОВАНИЕ

func deriveEncryptionKey(masterPassword, salt []byte) []byte {
	return argon2.IDKey(masterPassword, salt, 3, 128*1024, 4, 32)
}

func encryptPassword(masterKey []byte, plaintext string) (*EncryptedData, error) {
	salt := make([]byte, 32)
	rand.Read(salt)
	key := deriveEncryptionKey(masterKey, salt)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), nil)
	return &EncryptedData{
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
	}, nil
}

func decryptPassword(masterKey []byte, ed *EncryptedData) (string, error) {
	salt, _ := base64.StdEncoding.DecodeString(ed.Salt)
	ciphertext, _ := base64.StdEncoding.DecodeString(ed.Ciphertext)
	nonce, _ := base64.StdEncoding.DecodeString(ed.Nonce)
	key := deriveEncryptionKey(masterKey, salt)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", errors.New("неверный ключ")
	}
	return string(plaintext), nil
}

func hashPassword(password string) (string, string) {
	salt := make([]byte, 32)
	rand.Read(salt)
	hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	return base64.StdEncoding.EncodeToString(hash), base64.StdEncoding.EncodeToString(salt)
}

func verifyPassword(password, storedHash, storedSalt string) bool {
	salt, _ := base64.StdEncoding.DecodeString(storedSalt)
	hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	expectedHash, _ := base64.StdEncoding.DecodeString(storedHash)
	return sha256.Sum256(hash) == sha256.Sum256(expectedHash)
}

//ХРАНИЛИЩЕ НА ЯНДЕКС.ДИСКЕ

func loadStorage(chatID int64) *Storage {
	filename := fmt.Sprintf("/password-bot/storage_%d.json", chatID)

	client := &http.Client{Timeout: 10 * time.Second}
	req, _ := http.NewRequest("GET", webdavURL+filename, nil)
	req.SetBasicAuth(webdavUser, webdavPass)

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return &Storage{Passwords: []PasswordEntry{}}
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	var storage Storage
	json.Unmarshal(data, &storage)
	return &storage
}

func saveStorage(chatID int64, storage *Storage) {
	filename := fmt.Sprintf("/password-bot/storage_%d.json", chatID)
	data, _ := json.MarshalIndent(storage, "", "  ")

	client := &http.Client{Timeout: 10 * time.Second}

	req, _ := http.NewRequest("MKCOL", webdavURL+"/password-bot/", nil)
	req.SetBasicAuth(webdavUser, webdavPass)
	client.Do(req)

	// Сохраняем файл
	req, _ = http.NewRequest("PUT", webdavURL+filename, bytes.NewReader(data))
	req.SetBasicAuth(webdavUser, webdavPass)
	req.Header.Set("Content-Type", "application/json")
	client.Do(req)
}

//ОБРАБОТКА

func handleMessage(msg *tgbotapi.Message) {
	chatID := msg.Chat.ID
	text := msg.Text

	if sessions[chatID] == nil {
		sessions[chatID] = &UserSession{
			ChatID:  chatID,
			storage: loadStorage(chatID),
		}
	}
	session := sessions[chatID]

	if !session.IsLoggedIn {
		if text == "/start" {
			bot.Send(tgbotapi.NewMessage(chatID,
				"🔐 менеджер паролей\n\nотправьте мастер-пароль для входа.\nнет аккаунта? создайте новый вводом пароля (мин. 12 символов). ПРОЧИТАТЬ ИНСТРУКЦИЮ"))
			return
		}
		if len(session.storage.MasterHash) == 0 {
			if len(text) < 12 {
				bot.Send(tgbotapi.NewMessage(chatID, "❌ минимум 12 символов!"))
				return
			}
			hash, salt := hashPassword(text)
			session.storage.MasterHash = hash
			session.storage.MasterSalt = salt
			session.MasterKey = argon2.IDKey([]byte(text), []byte(salt), 1, 64*1024, 4, 32)
			session.IsLoggedIn = true
			saveStorage(chatID, session.storage)
			bot.Request(tgbotapi.NewDeleteMessage(chatID, msg.MessageID))
			bot.Send(tgbotapi.NewMessage(chatID, "✅ аккаунт создан!\n\n/add ЗАМЕТКА ПАРОЛЬ\n/list\n/get ID\n/delete ID\n/logout\n/backup\n/instruction"))
			return
		}
		if verifyPassword(text, session.storage.MasterHash, session.storage.MasterSalt) {
			session.MasterKey = argon2.IDKey([]byte(text), []byte(session.storage.MasterSalt), 1, 64*1024, 4, 32)
			session.IsLoggedIn = true
			bot.Request(tgbotapi.NewDeleteMessage(chatID, msg.MessageID))
			bot.Send(tgbotapi.NewMessage(chatID, "✅ вход выполнен!\n\n/add ЗАМЕТКА ПАРОЛЬ\n/list\n/get ID\n/delete ID\n/logout\n/backup\n/instruction"))
		} else {
			bot.Send(tgbotapi.NewMessage(chatID, "❌ неверный пароль!"))
		}
		return
	}

	switch {
	case strings.HasPrefix(text, "/add "):
		parts := strings.SplitN(text, " ", 3)
		if len(parts) < 3 {
			bot.Send(tgbotapi.NewMessage(chatID, "формат: /add ЗАМЕТКА ПАРОЛЬ"))
			return
		}
		note, password := parts[1], parts[2]
		encrypted, _ := encryptPassword(session.MasterKey, password)
		encryptedJSON, _ := json.Marshal(encrypted)
		entry := PasswordEntry{
			ID:        uuid.New().String()[:8],
			Note:      note,
			Data:      string(encryptedJSON),
			CreatedAt: time.Now().Format("02.01.2006 15:04"),
		}
		session.storage.Passwords = append(session.storage.Passwords, entry)
		saveStorage(chatID, session.storage)
		bot.Request(tgbotapi.NewDeleteMessage(chatID, msg.MessageID))
		bot.Send(tgbotapi.NewMessage(chatID, fmt.Sprintf("✅ '%s' сохранен! ID: %s", note, entry.ID)))

	case text == "/list":
		if len(session.storage.Passwords) == 0 {
			bot.Send(tgbotapi.NewMessage(chatID, "📭 Пусто"))
			return
		}
		resp := "📋пароли:\n\n"
		for _, e := range session.storage.Passwords {
			resp += fmt.Sprintf("🔹 %s (ID: %s)\n   📅 %s\n\n", e.Note, e.ID, e.CreatedAt)
		}
		bot.Send(tgbotapi.NewMessage(chatID, resp))

	case strings.HasPrefix(text, "/get "):
		id := strings.TrimPrefix(text, "/get ")
		for _, e := range session.storage.Passwords {
			if e.ID == id {
				var ed EncryptedData
				json.Unmarshal([]byte(e.Data), &ed)
				pass, _ := decryptPassword(session.MasterKey, &ed)
				sent, _ := bot.Send(tgbotapi.NewMessage(chatID, fmt.Sprintf("🔑 %s: %s", e.Note, pass)))
				go func() {
					time.Sleep(30 * time.Second)
					bot.Request(tgbotapi.NewDeleteMessage(chatID, sent.MessageID))
				}()
				return
			}
		}
		bot.Send(tgbotapi.NewMessage(chatID, "❌ не найдено"))

	case strings.HasPrefix(text, "/delete "):
		id := strings.TrimPrefix(text, "/delete ")
		for i, e := range session.storage.Passwords {
			if e.ID == id {
				session.storage.Passwords = append(session.storage.Passwords[:i], session.storage.Passwords[i+1:]...)
				saveStorage(chatID, session.storage)
				bot.Send(tgbotapi.NewMessage(chatID, fmt.Sprintf("🗑 '%s' удален!", e.Note)))
				return
			}
		}
		bot.Send(tgbotapi.NewMessage(chatID, "❌ не найдено"))

	case text == "/logout":
		delete(sessions, chatID)
		bot.Send(tgbotapi.NewMessage(chatID, "👋 вы вышли."))

	case text == "/backup":
		if len(session.storage.Passwords) == 0 {
			bot.Send(tgbotapi.NewMessage(chatID, "📭 нечего бекапить"))
			return
		}
		type BackupEntry struct {
			Note string `json:"note"`
			Pass string `json:"pass"`
		}
		var entries []BackupEntry
		for _, e := range session.storage.Passwords {
			var ed EncryptedData
			json.Unmarshal([]byte(e.Data), &ed)
			pass, _ := decryptPassword(session.MasterKey, &ed)
			entries = append(entries, BackupEntry{Note: e.Note, Pass: pass})
		}
		backupJSON, _ := json.Marshal(entries)
		encrypted, _ := encryptPassword(session.MasterKey, string(backupJSON))
		encJSON, _ := json.Marshal(encrypted)
		msg := fmt.Sprintf("📦 бекап от %d\n\n%s", chatID, string(encJSON))
		bot.Send(tgbotapi.NewMessage(backupChannel, msg))
		bot.Send(tgbotapi.NewMessage(chatID, "✅ бекап сохранен в защищенном канале!"))

	case text == "/instruction":
		bot.Send(tgbotapi.NewMessage(chatID,
			"📘 Инструкция:\n\n"+
				"/add ЗАМЕТКА ПАРОЛЬ — сохранить пароль, пример: гугл 1234567\n"+
				"/list — список всех паролей\n"+
				"/get ID — получить пароль\n"+
				"/delete ID — удалить пароль\n"+
				"/backup — сохранить бекап в канал\n"+
				"/logout — выйти\n\n"+
				"пароли шифруются AES-256-GCM.\n"+
				"без мастер-пароля доступ невозможен.\n"+
				"AСHTUNG! после отправки вашего пароля выполните команду бэкап, она сохранит пароль навсегда и можно выходить"))
	}
}

func main() {
	token := os.Getenv("BOT_TOKEN")
	if token == "" {
		log.Fatal("BOT_TOKEN не задан")
	}

	var err error
	bot, err = tgbotapi.NewBotAPI(token)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("бот %s запущен", bot.Self.UserName)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	appURL := os.Getenv("RENDER_EXTERNAL_URL")
	if appURL != "" {
		webhookURL := appURL + "/webhook"
		wh, _ := tgbotapi.NewWebhook(webhookURL)
		bot.Request(wh)
		log.Printf("вебхук: %s", webhookURL)
	}

	http.HandleFunc("/webhook", func(w http.ResponseWriter, r *http.Request) {
		update, _ := bot.HandleUpdate(r)
		if update != nil && update.Message != nil {
			handleMessage(update.Message)
		}
		w.WriteHeader(http.StatusOK)
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})

	log.Fatal(http.ListenAndServe(":"+port, nil))
}
