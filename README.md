# pishguard-ai
# 🛡️ PhishGuard AI

A lightweight, explainable phishing email detector built with NLP and Machine Learning.

🚀 **[Live Demo on Hugging Face Spaces](https://huggingface.co/spaces/BernardoCarvalho/pishguard-ai)**

---

## What it does

PhishGuard AI analyzes an email's subject and body and returns:

- **Verdict** — phishing or legitimate
- **Confidence score** — how certain the model is
- **Red flags** — the specific words and patterns that triggered the alert

The goal was never just accuracy — it was *explainability*. A detector that says "this is phishing because of these specific words" is far more useful than a black box.

---

## How it was built

The project started as an exploratory analysis on [Zerve](https://zerve.ai), an AI-native data science platform. The workflow:

1. **Exploratory Analysis** — investigated what makes phishing emails different from legitimate ones. Key findings:
   - 100% of phishing emails in the dataset contained URLs; legitimate emails rarely did
   - Phishing emails used 4x more urgency-related words ("verify", "click now", "suspended")
   - Common subject patterns: fake prizes, account warnings, password resets

2. **Feature Engineering** — combined subject + body text, extracted TF-IDF features with bigrams, and added rule-based signals for urgency words and suspicious links

3. **Model** — Logistic Regression with TF-IDF vectorization. Chosen deliberately for interpretability: the model's coefficients map directly to human-readable red flags

4. **Deployment** — Gradio app deployed on Hugging Face Spaces

---

## Results

| Metric | Score |
|--------|-------|
| Accuracy | 100% (on synthetic dataset) |
| Precision | 1.00 |
| Recall | 1.00 |
| F1 | 1.00 |

**Important caveat:** these numbers look great because the dataset is synthetic and small (300 samples). See limitations below.

---

## Limitations — and how we'd fix them

**1. Synthetic dataset**
The training data was generated, not collected from real phishing campaigns. This means the model learned clean, obvious patterns — not the subtle social engineering tactics used in real attacks.

*Fix: Train on a real labeled dataset like CEAS-08 or the Enron corpus combined with PhishTank samples.*

**2. False positives on legitimate institutional emails**
Banks and payment services legitimately use words like "account", "verify", and "immediately". The model currently flags these as phishing.

*Fix: Add a domain whitelist for known trusted senders, and train on a balanced dataset that includes legitimate emails from financial institutions.*

**3. No URL analysis**
The model only looks at whether a URL is present — not whether it's actually suspicious (shortened links, lookalike domains, mismatched anchors).

*Fix: Integrate a URL feature extractor that checks domain age, redirect chains, and lookalike detection.*

**4. English only**
The model was trained entirely on English text.

*Fix: Multilingual dataset + a language-aware tokenizer.*

---

## Stack

- Python 3.11
- scikit-learn (TF-IDF + Logistic Regression)
- Gradio (UI)
- Zerve (analysis and prototyping)
- Hugging Face Spaces (deployment)

---

## Run locally

```bash
git clone https://github.com/Bernardo-R-O-Carvalho/phishguard-ai
cd phishguard-ai
pip install -r requirements.txt
python app.py
```

---

## What's next

- [ ] Replace synthetic data with a real phishing corpus
- [ ] Add URL feature extraction
- [ ] Experiment with a fine-tuned DistilBERT for better generalization
- [ ] Build a browser extension version
- [ ] Add multilingual support

---

Built during the [Zerve Hackathon](https://zerve.ai)
