# 🛡️ PhishGuard AI
A phishing email detector built with NLP, Machine Learning, and rule-based analysis, trained on 27,859 real emails.

🚀 [Live Demo on Hugging Face Spaces](https://huggingface.co/spaces/BernardoCarvalho/pishguard-ai)

---

## What it does
PhishGuard AI analyzes an email's sender, subject, body, and metadata and returns:
- **Verdict** — PHISHING, SUSPICIOUS, or LEGITIMATE
- **Total risk score** — 0 to 100
- **Text analysis** — suspicious words score (0–50)
- **URL analysis** — lookalike domains, shortened links, missing HTTPS (0–50)
- **Sender analysis** — impersonation via free providers, lookalike domains (0–50)
- **Time analysis** — unusual send hours, weekends (0–20)
- **Pattern words** — additional phishing terms derived from dataset analysis
- **Word cloud** — visual of most frequent words in phishing emails

---

## How it works
1. Text is analyzed by a **DistilBERT multilingual model** (`distilbert-base-multilingual-cased`) fine-tuned on 27,859 real emails — supports 104 languages
2. A **URL feature extractor** analyzes every link in two layers:
   - Character substitution mapping (`0→o`, `1→l`, `rn→m`, etc.)
   - **Levenshtein distance** — fuzzy lookalike detection (`amazoon.com`, `arnazon.com`)
3. A **sender analyzer** detects impersonation patterns in the From field
4. A **time analyzer** flags emails sent at unusual hours (22h–06h) or on weekends
5. **Pattern words** derived from dataset word frequency add a small weighted score
6. All scores are combined into a final weighted total

**Model performance (fine-tuned DistilBERT, 10% validation set):**
- Accuracy: 99.2%
- F1-score: 0.993

---

## API
PhishGuard exposes a REST API via FastAPI:
POST /analyze
Content-Type: application/json
{
"sender": "paypal-support@gmail.com",
"subject": "Your account has been suspended",
"body": "Please verify your password at http://paypa1.com/secure/login",
"received_at": "Sun, 01 Jan 2024 03:45:00 +0000"
}

Response:
```json
{
  "verdict": "PHISHING",
  "total_score": 95,
  "model_confidence": 91,
  "text_score": 50,
  "url_score": 40,
  "sender_score": 30,
  "time_score": 20,
  "suspicious_words": ["verify", "account", "suspended", "password"],
  "pattern_words": [],
  "sender_flags": ["impersonating paypal.com via free email provider"],
  "time_flags": ["sent at unusual hour (03:45)", "sent on Sunday"],
  "received_parsed": "2024-01-01 03:45",
  "url_flags": ["paypa1.com: no HTTPS", "paypa1.com: impersonating paypal.com"]
}
```

Interactive docs available at `/docs`.

---

## Dataset
Trained on the **Enron Spam Dataset** (enron1, enron3, enron4, enron5, enron6):
- 15,675 spam/phishing emails
- 12,184 legitimate emails
- Source: [AUEB NLP Group](https://www2.aueb.gr/users/ion/data/enron-spam/)

---

## Project structure
phishguard-ai/
├── app.py                   # Gradio interface + analysis logic
├── api.py                   # FastAPI REST endpoint
├── url_features.py          # URL feature extraction + Levenshtein lookalike detection
├── sender_features.py       # Sender domain analysis
├── time_features.py         # Time-of-day and day-of-week analysis
├── wordcloud_gen.py         # Word cloud generation from dataset
├── train_model.py           # Original TF-IDF model training (v3)
├── setup_dataset.py         # Dataset download + preprocessing
├── phishguard-bert-final/   # Fine-tuned DistilBERT model
│   ├── config.json
│   ├── model.safetensors
│   ├── tokenizer.json
│   └── tokenizer_config.json
└── requirements.txt

---

## Running locally
```bash
python setup_dataset.py        # download and build dataset
python app.py                  # launch Gradio app (port 8080)
python -m uvicorn api:app --port 8001  # launch API
```

---

## What's next
- [ ] Browser extension (Chrome/Firefox) consuming the FastAPI endpoint
- [ ] Expand training data with CEAS-08 and PhishTank datasets for better generalization
- [ ] Multilingual phishing dataset for improved non-English detection

---

## Version history
- `main` — v4: DistilBERT multilingual (99.2% F1), Levenshtein fuzzy detection, time analysis (current)
- `v3` — granular score, URL/sender analysis, word cloud, FastAPI (tag: v3)
- `v2` — real dataset (27k emails), trained TF-IDF model, metrics
- `v1-original` — original prototype (synthetic data, 30 lines)


