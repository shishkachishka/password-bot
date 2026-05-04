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
	"strconv"
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
	ChatID         int64
	MasterKey      []byte
	IsLoggedIn     bool
	storage        *Storage
	waitingForFile bool
	addingNote     string // заметка при добавлении
	waitingForPass bool   // ждем пароль
	waitingForGet  bool   // ждем ID для получения
	waitingForDel  bool   // ждем ID для удаления
}

var (
	sessions = make(map[int64]*UserSession)
	bot      *tgbotapi.BotAPI

	// Яндекс.Диск
	webdavUser = os.Getenv("WEBDAV_USER")
	webdavPass = os.Getenv("WEBDAV_PASS")
	webdavURL  = "https://webdav.yandex.ru"
)

// КНОПКИ

func getMainKeyboard() tgbotapi.ReplyKeyboardMarkup {
	return tgbotapi.NewReplyKeyboard(
		tgbotapi.NewKeyboardButtonRow(
			tgbotapi.NewKeyboardButton("➕ Добавить пароль"),
			tgbotapi.NewKeyboardButton("📋 Список"),
		),
		tgbotapi.NewKeyboardButtonRow(
			tgbotapi.NewKeyboardButton("🔑 Получить пароль"),
			tgbotapi.NewKeyboardButton("🗑 Удалить"),
		),
		tgbotapi.NewKeyboardButtonRow(
			tgbotapi.NewKeyboardButton("📤 Экспорт"),
			tgbotapi.NewKeyboardButton("📥 Импорт"),
		),
		tgbotapi.NewKeyboardButtonRow(
			tgbotapi.NewKeyboardButton("🆔 Мой ID"),
			tgbotapi.NewKeyboardButton("📘 Инструкция"),
		),
		tgbotapi.NewKeyboardButtonRow(
			tgbotapi.NewKeyboardButton("🚪 Выйти"),
		),
	)
}

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

// ХРАНИЛИЩЕ НА ЯНДЕКС.ДИСКЕ

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
	data, _ := json.Marshal(storage)

	client := &http.Client{Timeout: 10 * time.Second}

	req, _ := http.NewRequest("MKCOL", webdavURL+"/password-bot/", nil)
	req.SetBasicAuth(webdavUser, webdavPass)
	client.Do(req)

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

	// Обработка импорта файла
	if session.waitingForFile && msg.Document != nil {
		session.waitingForFile = false
		fileID := msg.Document.FileID
		file, err := bot.GetFile(tgbotapi.FileConfig{FileID: fileID})
		if err != nil {
			bot.Send(tgbotapi.NewMessage(chatID, "❌ не удалось получить файл"))
			return
		}
		url := fmt.Sprintf("https://api.telegram.org/file/bot%s/%s", bot.Token, file.FilePath)
		resp, _ := http.Get(url)
		if resp == nil {
			bot.Send(tgbotapi.NewMessage(chatID, "❌ ошибка скачивания"))
			return
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)

		var imported Storage
		if err := json.Unmarshal(data, &imported); err != nil {
			bot.Send(tgbotapi.NewMessage(chatID, "❌ неверный формат файла"))
			return
		}
		session.storage = &imported
		saveStorage(chatID, &imported)
		msg := tgbotapi.NewMessage(chatID, fmt.Sprintf("✅ импортировано %d паролей!", len(imported.Passwords)))
		msg.ReplyMarkup = getMainKeyboard()
		bot.Send(msg)
		return
	}

	if !session.IsLoggedIn {
		if text == "/start" {
			bot.Send(tgbotapi.NewMessage(chatID,
				fmt.Sprintf("🔐 менеджер паролей\n\n🆔 ваш ID: %d\n\nотправьте мастер-пароль для входа.\nнет аккаунта? создайте новый вводом пароля (мин. 12 символов).", chatID)))
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
			msg := tgbotapi.NewMessage(chatID, "✅ аккаунт создан!\nиспользуйте кнопки меню:")
			msg.ReplyMarkup = getMainKeyboard()
			bot.Send(msg)
			return
		}
		if verifyPassword(text, session.storage.MasterHash, session.storage.MasterSalt) {
			session.MasterKey = argon2.IDKey([]byte(text), []byte(session.storage.MasterSalt), 1, 64*1024, 4, 32)
			session.IsLoggedIn = true
			bot.Request(tgbotapi.NewDeleteMessage(chatID, msg.MessageID))
			msg := tgbotapi.NewMessage(chatID, "✅ вход выполнен!\nиспользуйте кнопки меню:")
			msg.ReplyMarkup = getMainKeyboard()
			bot.Send(msg)
		} else {
			bot.Send(tgbotapi.NewMessage(chatID, "❌ неверный пароль!"))
		}
		return
	}

	// Кнопки и состояния
	switch {
	// Добавление пароля (шаг 1 - заметка)
	case text == "➕ Добавить пароль":
		session.waitingForPass = true
		session.addingNote = ""
		bot.Send(tgbotapi.NewMessage(chatID, "📝 введите заметку:"))
		return

	// Ждем заметку
	case session.waitingForPass && session.addingNote == "":
		session.addingNote = text
		bot.Send(tgbotapi.NewMessage(chatID, fmt.Sprintf("📝 заметка: %s\n🔒 теперь введите пароль:", text)))
		return

	// Ждем пароль
	case session.waitingForPass && session.addingNote != "":
		password := text
		encrypted, _ := encryptPassword(session.MasterKey, password)
		encryptedJSON, _ := json.Marshal(encrypted)
		entry := PasswordEntry{
			ID:        uuid.New().String()[:8],
			Note:      session.addingNote,
			Data:      string(encryptedJSON),
			CreatedAt: time.Now().Format("02.01.2006 15:04"),
		}
		session.storage.Passwords = append(session.storage.Passwords, entry)
		saveStorage(chatID, session.storage)
		bot.Request(tgbotapi.NewDeleteMessage(chatID, msg.MessageID))
		msg := tgbotapi.NewMessage(chatID, fmt.Sprintf("✅ '%s' сохранен! ID: %s", entry.Note, entry.ID))
		msg.ReplyMarkup = getMainKeyboard()
		bot.Send(msg)
		session.addingNote = ""
		session.waitingForPass = false
		return

	// Список
	case text == "📋 Список":
		if len(session.storage.Passwords) == 0 {
			msg := tgbotapi.NewMessage(chatID, "📭 пусто")
			msg.ReplyMarkup = getMainKeyboard()
			bot.Send(msg)
			return
		}
		resp := "📋 пароли:\n\n"
		for _, e := range session.storage.Passwords {
			resp += fmt.Sprintf("🔹 %s (ID: %s)\n   📅 %s\n\n", e.Note, e.ID, e.CreatedAt)
		}
		msg := tgbotapi.NewMessage(chatID, resp)
		msg.ReplyMarkup = getMainKeyboard()
		bot.Send(msg)
		return

	// Получить пароль
	case text == "🔑 Получить пароль":
		session.waitingForGet = true
		bot.Send(tgbotapi.NewMessage(chatID, "🔍 введите ID пароля:"))
		return

	case session.waitingForGet:
		id := strings.TrimSpace(text)
		session.waitingForGet = false
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
				msg := tgbotapi.NewMessage(chatID, "✅ пароль показан выше (удалится через 30 сек)")
				msg.ReplyMarkup = getMainKeyboard()
				bot.Send(msg)
				return
			}
		}
		msg := tgbotapi.NewMessage(chatID, "❌ не найдено")
		msg.ReplyMarkup = getMainKeyboard()
		bot.Send(msg)
		return

	// Удалить
	case text == "🗑 Удалить":
		session.waitingForDel = true
		bot.Send(tgbotapi.NewMessage(chatID, "🗑 введите ID пароля для удаления:"))
		return

	case session.waitingForDel:
		id := strings.TrimSpace(text)
		session.waitingForDel = false
		for i, e := range session.storage.Passwords {
			if e.ID == id {
				session.storage.Passwords = append(session.storage.Passwords[:i], session.storage.Passwords[i+1:]...)
				saveStorage(chatID, session.storage)
				msg := tgbotapi.NewMessage(chatID, fmt.Sprintf("🗑 '%s' удален!", e.Note))
				msg.ReplyMarkup = getMainKeyboard()
				bot.Send(msg)
				return
			}
		}
		msg := tgbotapi.NewMessage(chatID, "❌ не найдено")
		msg.ReplyMarkup = getMainKeyboard()
		bot.Send(msg)
		return

	// Экспорт
	case text == "📤 Экспорт":
		if len(session.storage.Passwords) == 0 {
			msg := tgbotapi.NewMessage(chatID, "📭 нечего экспортировать")
			msg.ReplyMarkup = getMainKeyboard()
			bot.Send(msg)
			return
		}
		data, _ := json.MarshalIndent(session.storage, "", "  ")
		file := tgbotapi.NewDocument(chatID, tgbotapi.FileReader{
			Name:   fmt.Sprintf("passwords_%d.json", chatID),
			Reader: bytes.NewReader(data),
		})
		file.Caption = "🔐 ваш зашифрованный файл с паролями."
		bot.Send(file)
		msg := tgbotapi.NewMessage(chatID, "✅ файл отправлен!")
		msg.ReplyMarkup = getMainKeyboard()
		bot.Send(msg)
		return

	// Импорт
	case text == "📥 Импорт":
		session.waitingForFile = true
		bot.Send(tgbotapi.NewMessage(chatID, "📎 отправьте файл с паролями"))
		return

	// Мой ID
	case text == "🆔 Мой ID":
		msg := tgbotapi.NewMessage(chatID, fmt.Sprintf("🆔 ваш ID: %d\n\nиспользуйте для синхронизации с десктопной версией.", chatID))
		msg.ReplyMarkup = getMainKeyboard()
		bot.Send(msg)
		return

	// Инструкция
	case text == "📘 Инструкция":
		msg := tgbotapi.NewMessage(chatID,
			"📘 Инструкция:\n\n"+
				"➕ Добавить пароль — добавить новый пароль\n"+
				"📋 Список — показать все пароли\n"+
				"🔑 Получить пароль — получить по ID\n"+
				"🗑 Удалить — удалить пароль\n"+
				"📤 Экспорт — скачать файл с паролями\n"+
				"📥 Импорт — загрузить файл\n"+
				"🆔 Мой ID — показать Telegram ID\n"+
				"🚪 Выйти — выход\n\n"+
				"пароли шифруются AES-256-GCM.\n"+
				"без мастер-пароля доступ невозможен.")
		msg.ReplyMarkup = getMainKeyboard()
		bot.Send(msg)
		return

	// Выйти
	case text == "🚪 Выйти":
		delete(sessions, chatID)
		msg := tgbotapi.NewMessage(chatID, "👋 вы вышли.")
		msg.ReplyMarkup = tgbotapi.NewRemoveKeyboard(true)
		bot.Send(msg)
		return

	// Старые команды (совместимость)
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
		msg := tgbotapi.NewMessage(chatID, fmt.Sprintf("✅ '%s' сохранен! ID: %s", note, entry.ID))
		msg.ReplyMarkup = getMainKeyboard()
		bot.Send(msg)

	case text == "/list", text == "/get", text == "/delete", text == "/export", text == "/import", text == "/myid", text == "/instruction", text == "/logout":
		msg := tgbotapi.NewMessage(chatID, "используйте кнопки меню 👇")
		msg.ReplyMarkup = getMainKeyboard()
		bot.Send(msg)
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

	http.HandleFunc("/api/load", func(w http.ResponseWriter, r *http.Request) {
		idStr := r.URL.Query().Get("id")
		id, _ := strconv.ParseInt(idStr, 10, 64)
		storage := loadStorage(id)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(storage)
	})

	http.HandleFunc("/api/save", func(w http.ResponseWriter, r *http.Request) {
		idStr := r.URL.Query().Get("id")
		id, _ := strconv.ParseInt(idStr, 10, 64)
		var storage Storage
		json.NewDecoder(r.Body).Decode(&storage)
		saveStorage(id, &storage)
		w.Write([]byte("OK"))
	})

	log.Fatal(http.ListenAndServe(":"+port, nil))
}
