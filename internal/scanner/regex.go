package scanner

import (
	"fmt"
	"regexp"
)

// Rule описывает правило поиска утечек
type Rule struct {
	Name    string
	Pattern *regexp.Regexp
}

// Security by Default: Запрет на хардкод. Отлавливаем стандартизированные токены.
var Rules = []Rule{
	{Name: "AWS Access Key", Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{Name: "GitHub Token", Pattern: regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`)},
	{Name: "Stripe API Key", Pattern: regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24}`)},
	{Name: "RSA Private Key", Pattern: regexp.MustCompile(`-----BEGIN (RSA|OPENSSH|PRIVATE) KEY-----`)},
	{Name: "Generic Password", Pattern: regexp.MustCompile(`(?i)(password|passwd|pwd|secret|token)\s*[:=]\s*["'][^"']+["']`)},
}

// ScanText прогоняет содержимое файла через все регулярные выражения
func ScanText(filename, content string) error {
	for _, rule := range Rules {
		if rule.Pattern.MatchString(content) {
			return fmt.Errorf("критическая утечка данных (%s)", rule.Name)
		}
	}
	return nil
}
