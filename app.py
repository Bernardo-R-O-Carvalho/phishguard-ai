import gradio as gr
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from url_features import analyze_email_urls
from sender_features import analyze_sender
from wordcloud_gen import generate_wordcloud
from time_features import analyze_time

import os
MODEL_PATH = os.path.join(os.path.dirname(__file__), "phishguard-bert-final")
tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
bert_model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH)
bert_model.eval()

RISK_WORDS = ["verify", "account", "click", "claim", "free", "urgent",
              "suspended", "password", "winner", "confirm", "update"]

WORDCLOUD_WORDS = [
    "money", "investment", "bank", "dollars", "pills", "link",
    "online", "security", "offer", "stock", "price", "million",
    "internet", "website", "address", "save", "info", "receive"
]

def get_model_confidence(text):
    inputs = tokenizer(text, return_tensors="pt", truncation=True, max_length=256, padding=True)
    with torch.no_grad():
        outputs = bert_model(**inputs)
    probs = torch.softmax(outputs.logits, dim=1)
    return int(probs[0][1].item() * 100)

def score_text(text, flags):
    base = 50 if len(flags) >= 3 else 25 if len(flags) >= 1 else 0
    return min(base + len(flags) * 5, 50)

def score_urls(url_results):
    if not url_results:
        return 0
    score = 0
    for r in url_results:
        if "trusted domain" in r["flags"]:
            continue
        if any("impersonating" in f for f in r["flags"]):
            score += 30
        if "shortened link" in r["flags"]:
            score += 15
        if "no HTTPS" in r["flags"]:
            score += 10
        if "suspicious word in domain" in r["flags"]:
            score += 10
    return min(score, 50)

def score_sender(sender_flags):
    if not sender_flags:
        return 0
    score = 0
    for f in sender_flags:
        if "impersonating" in f:
            score += 30
        elif "suspicious word" in f:
            score += 15
        elif "numbers" in f:
            score += 10
    return min(score, 50)

def score_wordcloud(text):
    hits = [w for w in WORDCLOUD_WORDS if w in text.lower()]
    return min(len(hits) * 3, 15)

def predict(sender, subject, body, received_at):
    text = subject + " " + body

    model_confidence = get_model_confidence(text)

    flags = [w for w in RISK_WORDS if w in text.lower()]
    url_results = analyze_email_urls(text)
    sender_flags = analyze_sender(sender)
    wc_hits = [w for w in WORDCLOUD_WORDS if w in text.lower()]
    wc_score = score_wordcloud(text)
    time_result = analyze_time(received_at)

    text_score = score_text(text, flags)
    url_score = score_urls(url_results)
    sndr_score = score_sender(sender_flags)
    time_score = time_result["score"]

    print(f"DEBUG - model: {model_confidence}, text: {text_score}, url: {url_score}, sender: {sndr_score}, wc: {wc_score}, time: {time_score}")

    total_score = min(
        int(model_confidence * 0.4) +
        int((text_score * 2) * 0.2) +
        int((url_score * 2) * 0.2) +
        int((sndr_score * 2) * 0.1) +
        wc_score +
        time_score,
        100
    )

    if total_score >= 80:
        verdict = "🚨 PHISHING — High risk"
    elif total_score >= 50:
        verdict = "⚠️ SUSPICIOUS — Moderate risk"
    else:
        verdict = "✅ LEGITIMATE"

    url_flags = []
    for r in url_results:
        for f in r["flags"]:
            if f != "trusted domain":
                url_flags.append(f"{r['domain']}: {f}")

    result = f"{verdict}\n"
    result += f"{'─' * 35}\n"
    result += f"Total risk score:  {total_score}/100\n\n"
    result += f"📝 Text analysis:   {text_score}/50  ({len(flags)} suspicious words)\n"
    result += f"🔗 URL analysis:    {url_score}/50  ({len(url_results)} URLs found)\n"
    result += f"📧 Sender analysis: {sndr_score}/50  ({len(sender_flags)} flags)\n"
    result += f"🕐 Time analysis:   {time_score}/20"
    if time_result["parsed"]:
        result += f"  ({time_result['parsed']})"
    result += "\n"
    result += f"{'─' * 35}\n"

    if flags:
        result += f"\nSuspicious words: {', '.join(flags)}\n"
    if wc_hits:
        result += f"Pattern words: {', '.join(wc_hits)}\n"
    if time_result["flags"]:
        result += f"\nTime flags:\n"
        for tf in time_result["flags"]:
            result += f"  ⚠️ {tf}\n"
    if sender_flags:
        result += f"\nSender flags:\n"
        for sf in sender_flags:
            result += f"  ⚠️ {sf}\n"
    if url_flags:
        result += f"\nURL flags:\n"
        for uf in url_flags:
            result += f"  ⚠️ {uf}\n"
    if url_results:
        result += f"\nURLs found:\n"
        for r in url_results:
            status = "✅" if "trusted domain" in r["flags"] else "⚠️"
            result += f"  {status} {r['domain']}\n"

    return result

with gr.Blocks() as demo:
    gr.Markdown("# 🛡️ PhishGuard AI\nDetect phishing emails using ML + rule-based analysis.")
    with gr.Tabs():
        with gr.Tab("🔍 Analyze Email"):
            sender = gr.Textbox(label="From (sender email)")
            subject = gr.Textbox(label="Subject")
            body = gr.Textbox(label="Body", lines=4)
            received_at = gr.Textbox(
                label="Date received (optional)",
                placeholder="e.g. Mon, 01 Jan 2024 03:45:00 +0000"
            )
            btn = gr.Button("Analyze", variant="primary")
            output = gr.Textbox(label="Result", lines=16)
            btn.click(predict, inputs=[sender, subject, body, received_at], outputs=output)
        with gr.Tab("☁️ Phishing Word Cloud"):
            gr.Markdown("### Most frequent words found in phishing emails (Enron dataset)")
            wc_image = gr.Image(value=generate_wordcloud(), label="Word Cloud", show_label=False)

demo.launch(server_name="0.0.0.0", server_port=7860, ssr_mode=False)