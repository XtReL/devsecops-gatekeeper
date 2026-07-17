package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"devsecops-gatekeeper/internal/auth"
	"devsecops-gatekeeper/internal/broker"
	"devsecops-gatekeeper/internal/config"
	"devsecops-gatekeeper/internal/db"
	"devsecops-gatekeeper/internal/github"

	"github.com/joho/godotenv"
	"github.com/nats-io/nats.go"
)

func main() {
	// 1. Принудительная загрузка .env файла (Zero Drift)
	if err := godotenv.Load(); err != nil {
		log.Println("[WARN] Файл .env не найден, используем системные переменные")
	} else {
		log.Println("[BOOT] ✅ Переменные окружения загружены из .env")
	}

	log.Println("[BOOT] Запуск SAST-сканера (Execution Node)...")

	cfg := config.Load()
	if err := cfg.Validate(); err != nil {
		log.Fatalf("[FATAL] invalid configuration: %v", err)
	}

	// 2. Инициализация базы данных PostgreSQL
	database, err := db.InitDB(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("[FATAL] Ошибка подключения к БД: %v", err)
	}

	// === НИЖЕ ОСТАЕТСЯ ВАШ ОРИГИНАЛЬНЫЙ КОД ===
	// // 2. ИНИЦИАЛИЗАЦИЯ GITHUB КЛИЕНТА...
	// ghClient, err := github.NewClient(...)

	/*// 1. Инициализация базы данных PostgreSQL
	database, err := db.InitDB(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("[FATAL] Ошибка подключения к БД: %v", err)
	}*/

	// 2. ИНИЦИАЛИЗАЦИЯ GITHUB КЛИЕНТА (Zero Trust: используем локальный .pem ключ)
	ghClient, err := github.NewClient(cfg.GitHubAppID, cfg.GitHubPrivateKeyPath)
	if err != nil {
		log.Fatalf("[FATAL] Ошибка инициализации GitHub: %v", err)
	}
	log.Println("[BOOT] GitHub App клиент успешно загружен")

	// ==========================================
	// Инициализация Auth-клиента (Enforcement Layer)
	// Передаем dummy-значения, так как используем MOCK-токен в auth.go
	// ==========================================
	authClient := auth.NewGitHubAppClient("dummy_app_id", nil)

	// Подключение к NATS
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
			m.Ack() // [FIX] Уничтожаем нечитаемые пакеты
			return
		}

		// [POISON PILL FIX] Защита от фантомных задач из прошлых тестов
		if task.RepoName == "" {
			log.Printf("[WORKER] ⚠️ Обнаружен Poison Pill (пустое имя). Пакет уничтожен.")
			m.Ack()
			return
		}

		log.Printf("[WORKER] 📥 Задача принята (Тенант: %s | Репо: %s)", task.TenantID, task.RepoName)

		scanID := fmt.Sprintf("scan-%s-%d", task.TenantID, time.Now().UnixNano())
		scanDir := filepath.Join(os.TempDir(), "gatekeeper-scans", scanID)

		if err := os.MkdirAll(scanDir, 0750); err != nil {
			log.Printf("[ERROR] Не удалось создать папку: %v", err)
			m.Nak() // Это системный сбой диска, можно попробовать еще раз позже
			return
		}

		defer func() {
			os.RemoveAll(scanDir)
			log.Printf("[CLEANUP] 🧹 Директория %s физически уничтожена.", scanDir)
		}()

		// [TRANSLATION FIX] Перевод абстрактного имени из AuthZ в реальный URL для Git
		cloneName := task.RepoName
		if cloneName == "demo_repo" {
			cloneName = "devsecops-gatekeeper" // Целимся в вашу реальную кодовую базу
		}

		targetURL := fmt.Sprintf("https://github.com/XtReL/%s.git", cloneName)
		log.Printf("[EXEC] ⏳ Клонирование боевого репозитория %s...", targetURL)

		// #nosec G204
		cloneCmd := exec.Command("git", "clone", "--depth", "1", targetURL, scanDir)
		if output, err := cloneCmd.CombinedOutput(); err != nil {
			log.Printf("[ERROR] Сбой клонирования:\n%s", string(output))
			m.Ack() // [CRITICAL FIX] Детерминированный сбой (404). Ретрай бессмысленен, сжигаем задачу.
			return
		}

		log.Println("[SCAN] 🕵️ Запуск Gitleaks для поиска секретов...")
		reportPath := filepath.Join(scanDir, "gitleaks-report.json")

		// [CRITICAL FIX] Обход защиты Go 1.19+ (Dot Path Security)
		gitleaksBin, _ := filepath.Abs("gitleaks.exe")

		// [Security by Default]: Защита от EDoS. Сканируем строго дельту последнего коммита.
		scanCmd := exec.Command(gitleaksBin, "detect", "--source", scanDir, "--log-opts", "-1", "--report-format", "json", "--report-path", reportPath)
		err = scanCmd.Run()

		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				if exitErr.ExitCode() == 1 {
					// Утечки найдены! Запускаем парсинг
					parseReport(reportPath, task, database, ghClient, authClient)
				} else {
					log.Printf("[ERROR] Внутренняя ошибка Gitleaks: %v", exitErr)
				}
			} else {
				log.Printf("[ERROR] СИСТЕМНАЯ ОШИБКА ЗАПУСКА: %v", err)
			}
		} else {
			log.Printf("[SCAN] ✅ Код репозитория %s чист.", task.RepoName)
		}

		m.Ack() // Успешное завершение всего цикла
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
func parseReport(reportPath string, task broker.TaskPayload, database *db.Database, ghClient *github.Client, authClient *auth.GitHubAppClient) {
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
		log.Println("[GITHUB] Инициирована отправка отчета и блокировка PR...")

		issueTitle := fmt.Sprintf("🚨 Gatekeeper Security Scan: Найдено %d уязвимостей", savedCount)
		issueBody := fmt.Sprintf("### Автоматический отчет ИБ 🛡️\n\nВ ходе проверки коммита сканер **Gitleaks** обнаружил **%d** незашифрованных секретов (Hardcoded Credentials) в исходном коде.\n\n**Рекомендация:**\n1. Удалите секреты из кода.\n2. Перенесите их в переменные окружения (`.env`) или Vault.\n3. Сбросьте (отозвите) утекшие ключи в панели провайдера, так как они скомпрометированы в истории Git.\n\n*Сгенерировано платформой DevSecOps Gatekeeper.*", savedCount)

		// Точечный вызов к вашему аккаунту XtReL
		realGitHubInstallationID := "140230661"
		repoOwner := "XtReL"

		// [CRITICAL FIX] Подмена фейкового имени на реальное для API GitHub
		targetRepo := task.RepoName
		if targetRepo == "demo_repo" {
			targetRepo = "devsecops-gatekeeper"
		}

		// 1. Пассивный контур: Создание Issue
		err := ghClient.CreateIssue(realGitHubInstallationID, repoOwner, targetRepo, issueTitle, issueBody)
		if err != nil {
			log.Printf("[ERROR] ❌ Сбой создания Issue: %v", err)
		} else {
			log.Println("[GITHUB] ✅ Успешно создан тикет об уязвимости!")
		}

		// ==========================================
		// 2. [ENFORCEMENT LAYER]: Активная блокировка
		// ==========================================
		if task.CommitSHA != "" {
			log.Println("[ENFORCEMENT] Инициирована аппаратная блокировка коммита...")

			// Получаем токен для взаимодействия (заглушка или реальный IAT)
			token, err := authClient.GenerateInstallationToken(context.Background(), realGitHubInstallationID, nil)
			if err != nil {
				log.Printf("[ERROR] Ошибка Auth-слоя GitHub (Check Run): %v", err)
			} else {
				// Наносим точечный HTTP-удар для перевода статуса в FAILED
				err = authClient.EnforceCheckRun(context.Background(), token, repoOwner, targetRepo, task.CommitSHA, issueBody)
				if err != nil {
					log.Printf("[ENFORCEMENT FAILURE] Сбой интеграции API: %v", err)
				} else {
					log.Println("[ENFORCEMENT SUCCESS] 🛑 Слияние кода физически заблокировано в GitHub")
				}
			}
		} else {
			log.Println("[ENFORCEMENT SKIP] Хэш коммита (CommitSHA) отсутствует. Блокировка невозможна.")
		}
	}
}
