#!/usr/bin/env python3
# ACT-0.1-RECHECK-2, пункт 5. Прямая загрузка логов заданий через REST API
# (/actions/jobs/<id>/logs) в окружении приёмки невозможна: API отвечает
# редиректом на productionresultssa6.blob.core.windows.net, egress-прокси
# отвечает на CONNECT 403 (политика организации). Логи получены через GitHub
# MCP (get_job_logs, return_content=true) - это тот же REST API, вызванный
# сервером MCP. Ответы MCP дословно хранятся в журнале сессии Claude Code
# (JSONL). Скрипт достаёт их оттуда без ручной перепечатки:
#   python3 -I p5-extract-mcp-logs.py <session.jsonl> <run-id> <jobs.json> <out-dir>
# Для каждого задания из <jobs.json> (ответ /actions/runs/<run-id>/jobs)
# пишет <out-dir>/run-<run-id>-job-<job-id>-<slug>.log (logs_content, UTF-8,
# без изменений) и печатает число строк против original_length из ответа MCP.
# Код выхода 1, если ответа MCP для какого-то задания нет или число строк
# не совпало.
import json
import re
import sys

transcript, run_id, jobs_path, out = sys.argv[1:5]
jobs = {j["id"]: j["name"] for j in json.load(open(jobs_path, encoding="utf-8"))["jobs"]}
found = {}
for line in open(transcript, encoding="utf-8"):
    try:
        e = json.loads(line)
    except ValueError:
        continue
    msg = e.get("message")
    if not isinstance(msg, dict) or not isinstance(msg.get("content"), list):
        continue
    for part in msg["content"]:
        if not isinstance(part, dict) or part.get("type") != "tool_result":
            continue
        cont = part.get("content")
        texts = [cont] if isinstance(cont, str) else [x.get("text", "") for x in cont or [] if isinstance(x, dict)]
        for t in texts:
            if '"logs_content"' not in t:
                continue
            d = json.loads(t)
            found[d["job_id"]] = d

rc = 0
for jid, name in sorted(jobs.items()):
    d = found.get(jid)
    if d is None:
        print(f"MISSING job {jid} {name!r}")
        rc = 1
        continue
    slug = re.sub(r"-+", "-", re.sub(r"[^A-Za-z0-9]", "-", name)).strip("-")
    path = f"{out}/run-{run_id}-job-{jid}-{slug}.log"
    text = d["logs_content"]
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(text)
    n = len(text.split("\n"))
    ok = n == d["original_length"]
    print(f"{'ok  ' if ok else 'FAIL'} job {jid} {name!r}: lines {n}, original_length {d['original_length']} -> {path}")
    if not ok:
        rc = 1
sys.exit(rc)
