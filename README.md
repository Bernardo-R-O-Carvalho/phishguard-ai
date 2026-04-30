# 🛡️ PhishGuard AI

A phishing email detector built with NLP and Machine Learning, trained on 27,859 real emails.

🚀 [Live Demo on Hugging Face Spaces](#) - offline

---

## What it does

PhishGuard AI analyzes an email's subject and body and returns:

- **Verdict** — phishing, suspicious, or legitimate
- **Risk score** — 0 to 100
- **Suspicious words** — flagged terms found in the text
- **URL analysis** — detects shortened links, missing HTTPS, lookalike domains (e.g. `amaz0n-tracking.com` imitating `amazon.com`)

---

## How it works

1. Text is vectorized using **TF-IDF** (5,000 features)
2. A **Logistic Regression** model classifies the email
3. A separate **URL feature extractor** analyzes every link in the email
4. Results are combined into a final risk score

**Model performance (test set, 20% holdout):**
- Accuracy: 99%
- Precision: 0.99
- Recall: 0.99
- F1-score: 0.99

---

## Dataset

Trained on the **Enron Spam Dataset** (enron1, enron3, enron4, enron5, enron6):
- 15,675 spam/phishing emails
- 12,184 legitimate emails
- Source: [AUEB NLP Group](https://www2.aueb.gr/users/ion/data/enron-spam/)

---

## Project structure
phishguard-ai/
├── app.py              # Gradio interface
├── train_model.py      # Model training + evaluation
├── setup_dataset.py    # Dataset download + preprocessing
├── url_features.py     # URL feature extraction
└── requirements.txt

## Running locally

```bash
python setup_dataset.py   # download and build dataset
python train_model.py     # train and save model
python app.py             # launch the app
```

---

## What's next

### Model
- [ ] Add CEAS-08 and PhishTank datasets
- [ ] Levenshtein distance for fuzzy lookalike domain detection
- [ ] Experiment with DistilBERT fine-tuning

### Product
- [ ] Granular risk score breakdown by category
- [ ] FastAPI endpoint
- [ ] Browser extension

### Analysis
- [ ] Word cloud of top phishing terms
- [ ] Sender domain pattern analysis
- [ ] Time-of-day analysis

---

## Version history

- `main` — current version (real dataset, URL analysis, risk score)
- `v1-original` — original prototype (synthetic data, 30 lines)
