package main

import (
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
	"os"
	"strings"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
)

// ===== ТЕ ЖЕ СХЕМЫ ШИФРОВАНИЯ ЧТО И В МЕНЕДЖЕРЕ =====

type EncryptedData struct {
	Ciphertext string `json:"ciphertext"`
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
}

type PasswordEntry struct {
	ID        string `json:"id"`
	Note      string `json:"note"`
	Data      string `json:"data"` // зашифрованный пароль
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

var sessions = make(map[int64]*UserSession)

// ШИФРОВАНИЕ

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
		return "", errors.New("неверный мастер-пароль")
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

// ХРАНИЛИЩЕ

func loadStorage(chatID int64) *Storage {
	filename := fmt.Sprintf("storage_%d.json", chatID)

	data, err := os.ReadFile(filename)
	if err != nil {
		return &Storage{Passwords: []PasswordEntry{}}
	}

	var storage Storage
	json.Unmarshal(data, &storage)
	return &storage
}

func saveStorage(chatID int64, storage *Storage) {
	filename := fmt.Sprintf("storage_%d.json", chatID)
	data, _ := json.MarshalIndent(storage, "", "  ")
	os.WriteFile(filename, data, 0600)
}

// ===== БОТ =====

func main() {
	token := "8433110993:AAErks6HXhmWNmkU4jZtdwRBbhAw5dj7IHo"

	bot, err := tgbotapi.NewBotAPI(token)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("бот %s запущен!\n", bot.Self.UserName)

	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60
	updates := bot.GetUpdatesChan(u)

	for update := range updates {
		if update.Message == nil {
			continue
		}

		msg := update.Message
		chatID := msg.Chat.ID
		text := msg.Text

		// Получаем или создаем сессию
		if sessions[chatID] == nil {
			sessions[chatID] = &UserSession{
				ChatID:  chatID,
				storage: loadStorage(chatID),
			}
		}
		session := sessions[chatID]

		// Если не авторизован
		if !session.IsLoggedIn {
			if text == "/start" {
				bot.Send(tgbotapi.NewMessage(chatID,
					"🔐 менеджер паролей\n\n"+
						"отправьте мастер-пароль для входа.\n"+
						"если у вас нет аккаунта, просто введите новый пароль."))
				continue
			}

			// Пытаемся войти или создать аккаунт
			if len(session.storage.MasterHash) == 0 {
				// Новый пользователь
				if len(text) < 12 {
					bot.Send(tgbotapi.NewMessage(chatID, "❌ пароль должен быть минимум 12 символов!"))
					continue
				}

				hash, salt := hashPassword(text)
				session.storage.MasterHash = hash
				session.storage.MasterSalt = salt

				// Создаем мастер-ключ
				session.MasterKey = argon2.IDKey(
					[]byte(text),
					[]byte(salt),
					1, 64*1024, 4, 32,
				)
				session.IsLoggedIn = true
				saveStorage(chatID, session.storage)

				// Удаляем сообщение с паролем
				bot.Request(tgbotapi.NewDeleteMessage(chatID, msg.MessageID))

				bot.Send(tgbotapi.NewMessage(chatID,
					"✅ аккаунт создан!\n\n"+
						"/add ЗАМЕТКА ПАРОЛЬ\n"+
						"/list\n"+
						"/get ID\n"+
						"/delete ID"))
				continue
			} else {
				// Существующий пользователь
				if verifyPassword(text, session.storage.MasterHash, session.storage.MasterSalt) {
					session.MasterKey = argon2.IDKey(
						[]byte(text),
						[]byte(session.storage.MasterSalt),
						1, 64*1024, 4, 32,
					)
					session.IsLoggedIn = true

					// Удаляем сообщение с паролем
					bot.Request(tgbotapi.NewDeleteMessage(chatID, msg.MessageID))

					bot.Send(tgbotapi.NewMessage(chatID,
						"✅ вход выполнен!\n\n"+
							"/add ЗАМЕТКА ПАРОЛЬ\n"+
							"/list\n"+
							"/get ID\n"+
							"/delete ID"))
				} else {
					bot.Send(tgbotapi.NewMessage(chatID, "❌ неверный мастер-пароль!"))
				}
				continue
			}
		}

		// Авторизован - обрабатываем команды
		switch {
		case strings.HasPrefix(text, "/add "):
			parts := strings.SplitN(text, " ", 3)
			if len(parts) < 3 {
				bot.Send(tgbotapi.NewMessage(chatID, "формат: /add ЗАМЕТКА ПАРОЛЬ"))
				continue
			}

			note := parts[1]
			password := parts[2]

			// Шифруем пароль (КАК В МЕНЕДЖЕРЕ)
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

			// Удаляем сообщение с паролем
			bot.Request(tgbotapi.NewDeleteMessage(chatID, msg.MessageID))

			bot.Send(tgbotapi.NewMessage(chatID,
				fmt.Sprintf("✅ пароль '%s' сохранен! ID: %s", note, entry.ID)))

		case text == "/list":
			if len(session.storage.Passwords) == 0 {
				bot.Send(tgbotapi.NewMessage(chatID, "📭 нет паролей"))
				continue
			}

			response := "📋 ваши пароли:\n\n"
			for _, entry := range session.storage.Passwords {
				response += fmt.Sprintf("🔹 %s (ID: %s)\n   📅 %s\n\n",
					entry.Note, entry.ID, entry.CreatedAt)
			}
			bot.Send(tgbotapi.NewMessage(chatID, response))

		case strings.HasPrefix(text, "/get "):
			id := strings.TrimPrefix(text, "/get ")

			for _, entry := range session.storage.Passwords {
				if entry.ID == id {
					// Расшифровываем пароль
					var encrypted EncryptedData
					json.Unmarshal([]byte(entry.Data), &encrypted)
					password, _ := decryptPassword(session.MasterKey, &encrypted)

					msg := fmt.Sprintf("🔑 %s: %s", entry.Note, password)
					sent, _ := bot.Send(tgbotapi.NewMessage(chatID, msg))

					// Удаляем через 30 секунд
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

			for i, entry := range session.storage.Passwords {
				if entry.ID == id {
					session.storage.Passwords = append(
						session.storage.Passwords[:i],
						session.storage.Passwords[i+1:]...,
					)
					saveStorage(chatID, session.storage)
					bot.Send(tgbotapi.NewMessage(chatID,
						fmt.Sprintf("🗑 '%s' удален!", entry.Note)))
					return
				}
			}
			bot.Send(tgbotapi.NewMessage(chatID, "❌ не найдено"))

		case text == "/logout":
			delete(sessions, chatID)
			bot.Send(tgbotapi.NewMessage(chatID, "👋 вы вышли из системы."))
		}
	}
}
