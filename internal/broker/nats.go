// internal/broker/nats.go
package broker

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
)

type NATSBroker struct {
	nc *nats.Conn
	js nats.JetStreamContext
}

// TaskPayload — структура данных, которая полетит в эфемерный K8s-контейнер
type TaskPayload struct {
	TenantID string `json:"tenant_id"`
	RepoName string `json:"repo_name"`
	Commit   string `json:"commit"`
	IAT      string `json:"iat"` // Тот самый токен, который мы достали из кэша
}

func NewNATSBroker(url string) (*NATSBroker, error) {
	// Подключаемся к NATS
	nc, err := nats.Connect(url, nats.Timeout(5*time.Second))
	if err != nil {
		return nil, fmt.Errorf("ошибка подключения к NATS: %w", err)
	}

	// Инициализируем JetStream (персистентная надстройка над NATS)
	js, err := nc.JetStream()
	if err != nil {
		return nil, fmt.Errorf("ошибка инициализации JetStream: %w", err)
	}

	// Автоматическое создание потока (Stream) для сканера, если он не существует
	streamName := "SAST_PIPELINE"
	_, err = js.StreamInfo(streamName)
	if err != nil {
		_, err = js.AddStream(&nats.StreamConfig{
			Name:     streamName,
			Subjects: []string{"sast.scan.>"}, // Роутинг по тенантам
			Storage:  nats.FileStorage,        // Сохранять на диск (защита от потери при рестарте)
			MaxAge:   2 * time.Hour,           // Удалять задачи старше 2 часов
		})
		if err != nil {
			return nil, fmt.Errorf("ошибка создания потока %s: %w", streamName, err)
		}
	}

	return &NATSBroker{nc: nc, js: js}, nil
}

// PublishTask публикует задачу в изолированный топик клиента
func (b *NATSBroker) PublishTask(task TaskPayload) error {
	// Формируем уникальный топик: sast.scan.12345
	subject := fmt.Sprintf("sast.scan.%s", task.TenantID)

	payload, err := json.Marshal(task)
	if err != nil {
		return err
	}

	// Асинхронная публикация (At-Least-Once delivery)
	_, err = b.js.Publish(subject, payload)
	return err
}
