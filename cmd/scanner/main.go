package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"devsecops-gatekeeper/internal/broker"
	"devsecops-gatekeeper/internal/config"
	"devsecops-gatekeeper/internal/db"
	"devsecops-gatekeeper/internal/github"

	"github.com/nats-io/nats.go"
)

func main() {
	log.Println("[BOOT] Запуск SAST-сканера (Execution Node)...")

	cfg := config.Load()
	if err := cfg.Validate(); err != nil {
		log.Fatalf("[FATAL] invalid configuration: %v", err)
	}

	// 1. Инициализация базы данных PostgreSQL
	database, err := db.InitDB(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("[FATAL] Ошибка подключения к БД: %v", err)
	}

	// 2. ИНИЦИАЛИЗАЦИЯ GITHUB КЛИЕНТА (Zero Trust: используем локальный .pem ключ)
	ghClient, err := github.NewClient(cfg.GitHubAppID, cfg.GitHubPrivateKeyPath)
	if err != nil {
		log.Fatalf("[FATAL] Ошибка инициализации GitHub: %v", err)
	}
	log.Println("[BOOT] GitHub App клиент успешно загружен")

	// 3. Подключение к NATS
	nc, err := nats.Connect(cfg.NATSURL)
	if err != nil {
		log.Fatalf("[FATAL] Ошибка NATS: %v", err)
	}
	defer nc.Close()

	js, err := nc.JetStream()
	if err != nil {
		log.Fatalf("[FATAL] Ошибка JetStream: %v", err)
	}

	// 4. Подписка на шину задач
	sub, err := js.QueueSubscribe("sast.scan.>", "scanner-workers-group", func(m *nats.Msg) {
		var task broker.TaskPayload
		if err := json.Unmarshal(m.Data, &task); err != nil {
			log.Printf("[ERROR] Ошибка парсинга: %v", err)
			m.Nak()
			return
		}

		log.Printf("[WORKER] 📥 Задача принята (Тенант: %s | Репо: %s)", task.TenantID, task.RepoName)

		scanID := fmt.Sprintf("scan-%s-%d", task.TenantID, time.Now().UnixNano())
		scanDir := filepath.Join(os.TempDir(), "gatekeeper-scans", scanID)

		if err := os.MkdirAll(scanDir, 0750); err != nil {
			log.Printf("[ERROR] Не удалось создать папку: %v", err)
			m.Nak()
			return
		}

		defer func() {
			os.RemoveAll(scanDir)
			log.Printf("[CLEANUP] 🧹 Директория %s физически уничтожена.", scanDir)
		}()

		// [PROD] Динамическое определение цели на основе метаданных задачи
		targetURL := fmt.Sprintf("https://github.com/XtReL/%s.git", task.RepoName)
		log.Printf("[EXEC] ⏳ Клонирование боевого репозитория %s...", targetURL)

		cloneCmd := exec.Command("git", "clone", "--depth", "1", targetURL, scanDir)
		if output, err := cloneCmd.CombinedOutput(); err != nil {
			log.Printf("[ERROR] Сбой клонирования:\n%s", string(output))
			m.Nak()
			return
		}

		log.Println("[SCAN] 🕵️ Запуск Gitleaks для поиска секретов...")
		reportPath := filepath.Join(scanDir, "gitleaks-report.json")

		scanCmd := exec.Command("gitleaks", "detect", "--source", scanDir, "--report-format", "json", "--report-path", reportPath)
		err = scanCmd.Run()

		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				if exitErr.ExitCode() == 1 {
					// ПЕРЕДАЕМ БАЗУ И GITHUB-КЛИЕНТ В ФУНКЦИЮ ПАРСИНГА
					parseReport(reportPath, task, database, ghClient)
				} else {
					log.Printf("[ERROR] Внутренняя ошибка Gitleaks: %v", exitErr)
				}
			} else {
				log.Printf("[ERROR] СИСТЕМНАЯ ОШИБКА ЗАПУСКА: %v", err)
			}
		} else {
			log.Printf("[SCAN] ✅ Код репозитория %s чист.", task.RepoName)
		}

		m.Ack()
	}, nats.ManualAck())

	if err != nil {
		log.Fatalf("[FATAL] Ошибка подписки: %v", err)
	}
	defer sub.Unsubscribe()

	log.Println("[READY] Worker готов к исполнению системных команд...")

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("[SHUTDOWN] Остановка сканера...")
}

// parseReport читает JSON от Gitleaks, сохраняет в БД и открывает Issue в GitHub
func parseReport(reportPath string, task broker.TaskPayload, database *db.Database, ghClient *github.Client) {
	// #nosec G304 - Имя файла отчета формируется детерминированно без участия пользователя
	reportData, err := os.ReadFile(reportPath)
	if err != nil {
		log.Printf("[ERROR] Не удалось прочитать отчет: %v", err)
		return
	}

	var findings []map[string]interface{}
	if err := json.Unmarshal(reportData, &findings); err != nil {
		log.Printf("[ERROR] Не удалось распарсить JSON: %v", err)
		return
	}

	log.Printf("[ALERT] 🚨 КРИТИЧЕСКИЙ РИСК: Найдено %d утечек!", len(findings))

	savedCount := 0
	for i, f := range findings {
		secret := f["Secret"].(string)
		rule := f["Description"].(string)
		file := f["File"].(string)

		// 1. МАСКИРОВАНИЕ (Защита от утечки в логи и БД)
		maskedSecret := secret
		if len(secret) > 6 {
			maskedSecret = secret[:6] + "***"
		} else {
			maskedSecret = "***"
		}

		if i < 2 {
			log.Printf("         -> [CVE] Правило: %s | Файл: %s | Секрет: %s", rule, file, maskedSecret)
		}

		// 2. СОХРАНЕНИЕ В БАЗУ ПОСТГРЕС
		finding := db.Finding{
			TenantID: task.TenantID,
			RepoName: task.RepoName,
			RuleID:   rule,
			FilePath: file,
			Secret:   maskedSecret,
		}

		if err := database.SaveFinding(finding); err != nil {
			log.Printf("[ERROR] Ошибка записи в БД: %v", err)
		} else {
			savedCount++
		}
	}

	log.Printf("[DB] 💾 Успешно сохранено %d записей об уязвимостях в PostgreSQL.", savedCount)

	// 3. ОТПРАВКА УВЕДОМЛЕНИЯ В GITHUB (Если есть уязвимости)
	if savedCount > 0 {
		log.Println("[GITHUB] Инициирована отправка отчета в удаленный репозиторий...")

		issueTitle := fmt.Sprintf("🚨 Gatekeeper Security Scan: Найдено %d уязвимостей", savedCount)
		issueBody := fmt.Sprintf("### Автоматический отчет ИБ 🛡️\n\nВ ходе проверки коммита сканер **Gitleaks** обнаружил **%d** незашифрованных секретов (Hardcoded Credentials) в исходном коде.\n\n**Рекомендация:**\n1. Удалите секреты из кода.\n2. Перенесите их в переменные окружения (`.env`) или Vault.\n3. Сбросьте (отозвите) утекшие ключи в панели провайдера, так как они скомпрометированы в истории Git.\n\n*Сгенерировано платформой DevSecOps Gatekeeper.*", savedCount)

		// Точечный вызов к вашему аккаунту XtReL
		err := ghClient.CreateIssue(task.TenantID, "XtReL", task.RepoName, issueTitle, issueBody)
		if err != nil {
			log.Printf("[ERROR] ❌ Сбой создания Issue: %v", err)
		} else {
			log.Println("[GITHUB] ✅ Успешно создан тикет об уязвимости!")
		}
	}
}
