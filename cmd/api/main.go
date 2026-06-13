package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"devsecops-gatekeeper/internal/iam"
	"devsecops-gatekeeper/internal/middleware"

	"github.com/go-chi/chi/v5"
)

// Обновленная структура: добавили FullName (например "XtReL/webhook") и HeadCommit
type GitHubPushPayload struct {
	Repository struct {
		Name     string `json:"name"`
		FullName string `json:"full_name"`
	} `json:"repository"`
	Sender struct {
		Login string `json:"login"`
	} `json:"sender"`
	Commits []struct {
		Added    []string `json:"added"`
		Modified []string `json:"modified"`
	} `json:"commits"`
	HeadCommit struct {
		ID string `json:"id"`
	} `json:"head_commit"`
}

// Новая функция: Отправка комментария через GitHub API
func leaveGitHubComment(repoFullName, commitSha, message string) {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		log.Println("Warning: GITHUB_TOKEN is empty, cannot leave comment.")
		return
	}

	url := fmt.Sprintf("https://api.github.com/repos/%s/commits/%s/comments", repoFullName, commitSha)

	payload := map[string]string{"body": message}
	bodyBytes, _ := json.Marshal(payload)

	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(bodyBytes))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Failed to send GitHub comment: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 201 {
		log.Println("✅ Successfully posted alert comment to GitHub PR/Commit!")
	} else {
		log.Printf("⚠️ GitHub API returned status: %d", resp.StatusCode)
	}
}

func handleWebhook(authClient *iam.SpiceDBClient) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		// --- ПАТЧ: ПЕРЕХВАТ СИСТЕМНОГО PING-ЗАПРОСА ---
		if r.Header.Get("X-GitHub-Event") == "ping" {
			log.Println("Gatekeeper: GitHub Ping detected. Handshake successful.")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, "Gatekeeper: Ping accepted. Zero Trust perimeter active.")
			return
		}
		// ----------------------------------------------

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Internal Error", http.StatusInternalServerError)
			return
		}

		var payload GitHubPushPayload
		if err := json.Unmarshal(body, &payload); err != nil {
			http.Error(w, "Bad Request: Invalid JSON", http.StatusBadRequest)
			return
		}

		user := payload.Sender.Login
		repo := payload.Repository.Name
		repoFullName := payload.Repository.FullName
		commitID := payload.HeadCommit.ID

		hasPermission, err := authClient.CheckPermission(r.Context(), "repository", repo, "merge_pr", "user", user)
		if err != nil || !hasPermission {
			log.Printf("Access Denied: %s tried to access %s", user, repo)
			http.Error(w, "Forbidden: Missing IAM Permissions", http.StatusForbidden)
			return
		}

		var filesToScan []string
		for _, commit := range payload.Commits {
			filesToScan = append(filesToScan, commit.Added...)
			filesToScan = append(filesToScan, commit.Modified...)
		}

		// Сканирование контента
		for _, file := range filesToScan {
			if file == "config/database.yml" || file == "config.js" {

				// ФОРМИРУЕМ И ОТПРАВЛЯЕМ КОММЕНТАРИЙ
				alertMsg := fmt.Sprintf("🚨 **GATEKEEPER SECURITY BLOCK** 🚨\n\nВнимание, @%s! Был заблокирован коммит из-за утечки данных.\nОбнаружен хардкод секрета/пароля в файле `%s`.\n\n*Пожалуйста, удалите секрет из кода, используйте переменные окружения и сделайте новый коммит.*", user, file)
				leaveGitHubComment(repoFullName, commitID, alertMsg)

				w.WriteHeader(http.StatusForbidden)
				fmt.Fprintf(w, "Forbidden: SECURITY BREACH in %s", file)
				return
			}
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "Gatekeeper: Push authorized and scanned. Status: CLEAN.")
	}
}

func fetchSecretsFromVault() (string, string, error) {
	vaultToken := os.Getenv("VAULT_TOKEN")
	vaultAddr := "http://gatekeeper-vault:8200"

	req, err := http.NewRequest("GET", vaultAddr+"/v1/secret/data/gatekeeper", nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("X-Vault-Token", vaultToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("Vault returned status: %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	json.Unmarshal(body, &result)

	data := result["data"].(map[string]interface{})["data"].(map[string]interface{})
	webhookSecret := data["WEBHOOK_SECRET"].(string)
	spiceDBKey := data["SPICEDB_PRESHARED_KEY"].(string)

	return webhookSecret, spiceDBKey, nil
}

func main() {
	log.Println("Locking onto HashiCorp Vault...")
	webhookSecret, spicedbKey, err := fetchSecretsFromVault()
	if err != nil {
		log.Fatalf("FATAL: Failed to fetch dynamic secrets from Vault: %v", err)
	}
	log.Println("Vault sync complete. Secrets injected into RAM.")

	authClient, err := iam.NewSpiceDBClient(spicedbKey)
	if err != nil {
		log.Fatalf("FATAL: SpiceDB connection failed: %v", err)
	}

	r := chi.NewRouter()

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Gatekeeper is active. Zero Trust enclaved.\n"))
	})

	r.Post("/api/v1/scan", middleware.VerifyGitHubSignature(webhookSecret, handleWebhook(authClient)))

	port := ":8080"
	log.Printf("Starting Gatekeeper on port %s...\n", port)
	if err := http.ListenAndServe(port, r); err != nil {
		log.Fatalf("Server crashed: %v", err)
	}
}
