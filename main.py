import os
import base64
import re
import json
import requests
import time
from dotenv import load_dotenv

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build


# Escopo simples para ler emails
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

load_dotenv()

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:3b")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434/api/generate")


PHISHING_KEYWORDS = [
    "urgente",
    "clique aqui",
    "verifique sua conta",
    "confirme sua conta",
    "confirme sua senha",
    "senha",
    "login",
    "pagamento pendente",
    "conta bloqueada",
    "atualize seus dados",
    "security alert",
    "reset password",
    "pix",
    "fatura",
    "premio",
    "prêmio",
    "gratuito"
]

SUSPICIOUS_TLDS = [".xyz", ".ru", ".top", ".click", ".shop"]


def gmail_auth():
    creds = None

    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                "credentials.json", SCOPES
            )
            creds = flow.run_local_server(port=0)

        with open("token.json", "w", encoding="utf-8") as token:
            token.write(creds.to_json())

    return build("gmail", "v1", credentials=creds)


def get_header(headers, name):
    for h in headers:
        if h["name"].lower() == name.lower():
            return h["value"]
    return ""


def decode_base64url(data):
    if not data:
        return ""
    missing_padding = len(data) % 4
    if missing_padding:
        data += "=" * (4 - missing_padding)
    return base64.urlsafe_b64decode(data).decode("utf-8", errors="ignore")


def extract_text_from_payload(payload):
    mime_type = payload.get("mimeType", "")
    body = payload.get("body", {})
    parts = payload.get("parts", [])

    if mime_type == "text/plain" and "data" in body:
        return decode_base64url(body["data"])

    if mime_type == "text/html" and "data" in body:
        html = decode_base64url(body["data"])
        return strip_html(html)

    for part in parts:
        part_mime = part.get("mimeType", "")
        part_body = part.get("body", {})

        if part_mime == "text/plain" and "data" in part_body:
            return decode_base64url(part_body["data"])

        if part_mime == "text/html" and "data" in part_body:
            html = decode_base64url(part_body["data"])
            return strip_html(html)

        if part.get("parts"):
            nested = extract_text_from_payload(part)
            if nested:
                return nested

    return ""


def strip_html(html):
    text = re.sub(r"<script.*?</script>", "", html, flags=re.S | re.I)
    text = re.sub(r"<style.*?</style>", "", text, flags=re.S | re.I)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def extract_links(text):
    return re.findall(r'https?://[^\s<>"\']+', text)


def basic_rules(sender, subject, body):
    text = f"{subject}\n{body}".lower()
    signals = []

    for keyword in PHISHING_KEYWORDS:
        if keyword in text:
            signals.append(f"keyword:{keyword}")

    links = extract_links(body)
    if links:
        signals.append(f"links:{len(links)}")

    sender_email_match = re.search(r"<(.+?)>", sender)
    sender_email = sender_email_match.group(1) if sender_email_match else sender

    sender_email = sender_email.strip().lower()

    if "@" in sender_email:
        domain = sender_email.split("@")[-1]
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                signals.append(f"suspicious_domain:{domain}")
                break

    if ("urgente" in text or "imediatamente" in text) and (
        "senha" in text or "login" in text or "conta" in text
    ):
        signals.append("social_engineering_urgency")

    score = min(len(signals) * 20, 100)
    return signals, links, score


def ask_ollama(sender, subject, body, links, signals, rule_score):
    prompt = f"""
Você é um analista de segurança de emails.
Classifique o email como:
- SEGURO
- SUSPEITO
- PHISHING

Responda APENAS em JSON válido neste formato:
{{
  "classificacao": "SEGURO|SUSPEITO|PHISHING",
  "score": 0,
  "motivos": ["motivo 1", "motivo 2"],
  "resumo": "texto curto"
}}

Considere:
- urgência excessiva
- tentativa de obter senha ou login
- links suspeitos
- engenharia social
- domínio estranho
- linguagem manipuladora

DADOS:
Remetente: {sender}
Assunto: {subject}
Links: {links}
Sinais por regra: {signals}
Pontuação por regra: {rule_score}
Corpo:
{body[:2000]}
""".strip()

    response = requests.post(
        OLLAMA_URL,
        json={
            "model": OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False
        },
        timeout=120
    )
    response.raise_for_status()

    raw = response.json()["response"].strip()
    parsed = try_parse_json(raw)
    if parsed is not None:
        return parsed

    return {
        "classificacao": "SUSPEITO",
        "score": rule_score,
        "motivos": ["Ollama não retornou JSON válido"],
        "resumo": raw[:500]
    }


def try_parse_json(text):
    if not text:
        return None

    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.I)
        cleaned = re.sub(r"\s*```$", "", cleaned, flags=re.I)

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None

    snippet = cleaned[start:end + 1]
    try:
        return json.loads(snippet)
    except json.JSONDecodeError:
        return None


def send_telegram_message(text):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": text
    }
    response = requests.post(url, json=payload, timeout=30)
    response.raise_for_status()


def get_latest_messages(service, max_results=5):
    result = service.users().messages().list(
        userId="me",
        labelIds=["INBOX"],
        maxResults=max_results
    ).execute()

    return result.get("messages", [])


def read_message(service, msg_id):
    msg = service.users().messages().get(
        userId="me",
        id=msg_id,
        format="full"
    ).execute()

    payload = msg.get("payload", {})
    headers = payload.get("headers", [])

    subject = get_header(headers, "Subject")
    sender = get_header(headers, "From")
    snippet = msg.get("snippet", "")
    body = extract_text_from_payload(payload)

    if not body:
        body = snippet

    return {
        "id": msg_id,
        "subject": subject,
        "from": sender,
        "body": body[:4000]
    }


def parse_score(value, fallback=0):
    if value is None:
        return fallback

    if isinstance(value, str):
        match = re.search(r"\d+", value)
        if not match:
            return fallback
        value = match.group(0)

    try:
        return int(value)
    except (ValueError, TypeError):
        return fallback


def analyze_scores(llm_result, rule_score):
    llm_score = parse_score(llm_result.get("score"), fallback=rule_score)
    classification = str(llm_result.get("classificacao", "")).strip().upper()
    final_score = max(rule_score, llm_score)
    should = final_score >= 60 or classification == "PHISHING"
    return should, final_score, llm_score, classification


def main():
    print("1. Iniciando main()")

    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        raise ValueError("Defina TELEGRAM_BOT_TOKEN e TELEGRAM_CHAT_ID no .env")

    print("2. Variáveis do .env carregadas")

    service = gmail_auth()
    print("3. Gmail autenticado")

    processed_ids = set()

    initial_messages = get_latest_messages(service, max_results=5)
    print("4. Mensagens iniciais buscadas")

    for msg in initial_messages:
        processed_ids.add(msg["id"])

    print(f"5. IDs iniciais salvos: {len(processed_ids)}")
    print("Monitorando emails novos da INBOX... Pressione Ctrl + C para parar.")

    while True:
        try:
            print("6. Verificando emails...")
            messages = get_latest_messages(service, max_results=5)
            print(f"7. Emails retornados: {len(messages)}")

            for item in reversed(messages):
                msg_id = item["id"]

                if msg_id in processed_ids:
                    continue

                print(f"8. Novo email encontrado: {msg_id}")
                processed_ids.add(msg_id)

                email = read_message(service, msg_id)
                print("9. Email lido")

                signals, links, rule_score = basic_rules(
                    email["from"], email["subject"], email["body"]
                )
                print("10. Regras aplicadas")

                llm_result = ask_ollama(
                    sender=email["from"],
                    subject=email["subject"],
                    body=email["body"],
                    links=links,
                    signals=signals,
                    rule_score=rule_score
                )
                print("11. Ollama respondeu")

                print("=" * 80)
                print("FROM:", email["from"])
                print("SUBJECT:", email["subject"])
                print("RULE SIGNALS:", signals)
                print("OLLAMA:", llm_result)

                should_send, final_score, llm_score, llm_class = analyze_scores(
                    llm_result, rule_score
                )
                print(
                    f"SCORES: regras={rule_score} llm={llm_score} final={final_score} class={llm_class}"
                )

                if should_send:
                    motivos = "\n- ".join(llm_result.get("motivos", []))
                    telegram_text = (
                        "⚠️ Alerta de email suspeito\n\n"
                        f"Remetente: {email['from']}\n"
                        f"Assunto: {email['subject']}\n"
                        f"Classificação: {llm_result.get('classificacao')}\n"
                        f"Score: {final_score} (regras {rule_score}, LLM {llm_score})\n\n"
                        f"Motivos:\n- {motivos}\n\n"
                        f"Resumo:\n{llm_result.get('resumo', '')}"
                    )
                    send_telegram_message(telegram_text)
                    print("12. Telegram enviado")

            time.sleep(10)

        except KeyboardInterrupt:
            print("\nMonitoramento encerrado.")
            break
        except Exception as e:
            print(f"Erro: {e}")
            time.sleep(10)


if __name__ == "__main__":
    main()
