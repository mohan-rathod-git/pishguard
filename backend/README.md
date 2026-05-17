# 🛡️ PhishGuard AI — Backend

Production-grade AI-powered cybersecurity backend for detecting phishing, spam, malware, and scam URLs.

## Architecture

```
backend/
├── app/
│   ├── api/            # FastAPI routes & schemas
│   ├── ml/             # ML prediction engine
│   ├── services/       # Threat scoring, reputation
│   ├── utils/          # Feature extraction, logging, sanitization
│   ├── models/         # Trained model files (.joblib)
│   ├── training/       # Training pipeline & CLI tester
│   ├── datasets/       # Blacklist/whitelist JSON
│   ├── config.py       # Settings
│   └── main.py         # FastAPI entry point
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
└── .env
```

## Quick Start

### 1. Install dependencies
```bash
cd backend
pip install -r requirements.txt
```

### 2. Train the model
```bash
python -m app.training.train_model
```

### 3. Run the API
```bash
python -m app.main
# or
uvicorn app.main:app --reload
```

### 4. Open API docs
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## API Endpoints

| Method | Endpoint             | Description                      |
|--------|----------------------|----------------------------------|
| POST   | `/api/v1/predict`     | Predict threat for a single URL  |
| POST   | `/api/v1/batch_predict` | Predict threats for up to 100 URLs |
| GET    | `/api/v1/health`      | Health check                     |
| GET    | `/api/v1/model-info`  | Model metadata                   |

## Example Request

```bash
curl -X POST http://localhost:8000/api/v1/predict \
  -H "Content-Type: application/json" \
  -d '{"url": "http://suspicious-login.xyz/verify-account"}'
```

## Example Response

```json
{
  "url": "http://suspicious-login.xyz/verify-account",
  "prediction": "PHISHING",
  "confidence": 0.9734,
  "risk_score": 87,
  "reasons": [
    "Contains 3 suspicious keyword(s) (login, verify, account, etc.)",
    "Uses a suspicious top-level domain (TLD)",
    "Does not use HTTPS encryption"
  ]
}
```

## CLI Testing

```bash
python -m app.training.cli_test --url "https://google.com"
python -m app.training.cli_test --batch
python -m app.training.cli_test --features "http://bit.ly/abc123"
```

## Docker

```bash
docker-compose up --build
```

## Features

- 🧠 XGBoost + RandomForest model comparison
- 📊 25+ URL features extracted
- 🔍 Explainable AI — human-readable reasons
- 🛡️ Blacklist / Whitelist with caching
- ⚡ Rate limiting and input sanitization
- 📈 Confidence scores + risk scores (0-100)
- 🐳 Docker-ready deployment
