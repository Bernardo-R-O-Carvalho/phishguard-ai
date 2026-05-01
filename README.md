# 🛡️ PhishGuard AI

A phishing email detector built with NLP, Machine Learning, and rule-based analysis, trained on 27,859 real emails.

🚀 [Live Demo on Hugging Face Spaces] - (huggingface.co/spaces/BernardoCarvalho/pishguard-ai)

---

## What it does

PhishGuard AI analyzes an email's sender, subject, and body and returns:

- **Verdict** — PHISHING, SUSPICIOUS, or LEGITIMATE
- **Total risk score** — 0 to 100
- **Text analysis** — suspicious words score (0–50)
- **URL analysis** — lookalike domains, shortened links, missing HTTPS (0–50)
- **Sender analysis** — impersonation via free providers, lookalike domains (0–50)
- **Pattern words** — additional phishing terms derived from dataset analysis
- **Word cloud** — visual of most frequent words in phishing emails

---

## How it works

1. Text is vectorized using **TF-IDF** (5,000 features)
2. A **Logistic Regression** model classifies the email
3. A **URL feature extractor** analyzes every link — lookalike detection uses character substitution mapping (`0→o`, `1→l`, `rn→m`, etc.)
4. A **sender analyzer** detects impersonation patterns in the From field
5. **Pattern words** derived from dataset word frequency add a small weighted score
6. All scores are combined into a final weighted total

**Model performance (test set, 20% holdout):**
- Accuracy: 99%
- Precision: 0.99
- Recall: 0.99
- F1-score: 0.99

---

## API

PhishGuard exposes a REST API via FastAPI:
POST /analyze
Content-Type: application/json
{
"sender": "paypal-support@gmail.com",
"subject": "Your account has been suspended",
"body": "Please verify your password at http://paypa1.com/secure/login"
}
Response:
```json
{
  "verdict": "PHISHING",
  "total_score": 85,
  "model_confidence": 88,
  "text_score": 50,
  "url_score": 40,
  "sender_score": 30,
  "suspicious_words": ["verify", "account", "suspended", "password"],
  "pattern_words": [],
  "sender_flags": ["impersonating paypal.com via free email provider"],
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
├── app.py              # Gradio interface + analysis logic
├── api.py              # FastAPI REST endpoint
├── url_features.py     # URL feature extraction + lookalike detection
├── sender_features.py  # Sender domain analysis
├── wordcloud_gen.py    # Word cloud generation from dataset
├── train_model.py      # Model training + evaluation
├── setup_dataset.py    # Dataset download + preprocessing
└── requirements.txt
## Running locally

```bash
python setup_dataset.py        # download and build dataset
python train_model.py          # train and save model
python app.py                  # launch Gradio app (port 8080)
python -m uvicorn api:app --port 8001  # launch API
```

---

## What's next

### Model
- [ ] Add CEAS-08 and PhishTank datasets
- [ ] Levenshtein distance for fuzzy lookalike domain detection
- [ ] Experiment with DistilBERT fine-tuning

### Product
- [ ] Browser extension (Chrome/Firefox) consuming the API
- [ ] Multilingual support — Portuguese, Spanish, etc.

### Analysis
- [ ] Sender domain pattern analysis
- [ ] Time-of-day analysis — phishing tends to arrive outside business hours

---

## Version history

- `main` — v3: granular score, URL/sender analysis, word cloud, FastAPI (current)
- `v2` — real dataset (27k emails), trained model, metrics
- `v1-original` — original prototype (synthetic data, 30 lines)
