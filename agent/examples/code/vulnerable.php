<?php
// Intentionally vulnerable sample for NTAgentShield code-scanner demonstration.
$api_key = "demo-super-secret-key";
$payload = base64_decode($_POST['payload']);
eval($payload);
$query = "SELECT * FROM users WHERE name='" . $_GET['name'] . "'";
echo shell_exec($_GET['cmd']);
