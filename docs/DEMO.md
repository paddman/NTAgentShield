# Demo script

1. Start Qwen on the A100 with `deploy/run-qwen-a100.sh`.
2. Start the API with `ntshield serve --port 8080`.
3. Open the dashboard and choose tenant `demo`.
4. Press **Replay attack chain**.
5. Show the sequence: novel POST -> `w3wp.exe` -> `powershell.exe` -> external TLS -> ASPX write.
6. Open the incident. Point out risk score, MITRE mapping and evidence IDs.
7. Press **Analyze with Qwen3.5-9B**.
8. Show that the embedded prompt-injection text in the request body is ignored and cannot whitelist
   the attacker IP.
9. Explain that the system calls this a bounded zero-day hypothesis, not a confirmed CVE.
