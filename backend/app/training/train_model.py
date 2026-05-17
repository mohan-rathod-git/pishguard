"""
PhishGuard AI — Model Training Pipeline
Loads the dataset, extracts features, trains XGBoost + RandomForest,
compares them, and saves the best model to disk.

Usage:
    python -m app.training.train_model
"""

import os
import sys
import time
import json
from pathlib import Path

import numpy as np
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)
from xgboost import XGBClassifier
from sklearn.ensemble import RandomForestClassifier

# ── Project imports ──
# Ensure project root is on the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from app.utils.feature_extractor import extract_features, get_feature_names
from app.config import settings


# ─────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────

DATASET_PATH = settings.DATASET_PATH
MODEL_OUTPUT = settings.MODEL_PATH
SCALER_OUTPUT = settings.SCALER_PATH
MAX_ROWS = settings.MAX_DATASET_ROWS
TEST_SIZE = 0.20
RANDOM_STATE = 42


def load_dataset(path: str, max_rows: int) -> pd.DataFrame:
    """Load and clean the URL dataset."""
    print(f"\n{'='*60}")
    print(f"  📂 Loading dataset from: {path}")
    print(f"{'='*60}")

    df = pd.read_csv(
        path,
        names=["url", "label"],
        header=0,
        nrows=max_rows,
        encoding="utf-8",
        on_bad_lines="skip",
    )

    print(f"  Raw rows loaded: {len(df):,}")

    # ── Clean ──
    df = df.dropna(subset=["url", "label"])
    df = df.drop_duplicates(subset=["url"])
    df["label"] = pd.to_numeric(df["label"], errors="coerce")
    df = df.dropna(subset=["label"])
    df["label"] = df["label"].astype(int)

    # Keep only valid labels (0=phishing, 1=safe)
    df = df[df["label"].isin([0, 1])]

    print(f"  Cleaned rows:    {len(df):,}")
    print(f"  Label distribution:")
    for label, count in df["label"].value_counts().items():
        tag = "PHISHING" if label == 0 else "SAFE"
        print(f"    {tag} ({label}): {count:,}")

    return df.reset_index(drop=True)


def extract_all_features(urls: pd.Series) -> pd.DataFrame:
    """Extract features for all URLs with a progress indicator."""
    print(f"\n{'='*60}")
    print(f"  🔬 Extracting features for {len(urls):,} URLs...")
    print(f"{'='*60}")

    feature_names = get_feature_names()
    features_list = []
    total = len(urls)
    start = time.time()

    for i, url in enumerate(urls):
        try:
            feats = extract_features(str(url))
            features_list.append(feats)
        except Exception:
            # On extraction failure, use zeros
            features_list.append({f: 0.0 for f in feature_names})

        # Progress every 10%
        if (i + 1) % max(1, total // 10) == 0:
            elapsed = time.time() - start
            pct = (i + 1) / total * 100
            rate = (i + 1) / elapsed if elapsed > 0 else 0
            remaining = (total - i - 1) / rate if rate > 0 else 0
            print(f"    ⏳ {pct:5.1f}% ({i+1:,}/{total:,}) — {rate:.0f} URLs/s — ~{remaining:.0f}s left")

    elapsed = time.time() - start
    print(f"  ✅ Feature extraction completed in {elapsed:.1f}s")

    return pd.DataFrame(features_list, columns=feature_names)


def train_and_evaluate(
    X_train: np.ndarray,
    X_test: np.ndarray,
    y_train: np.ndarray,
    y_test: np.ndarray,
    model,
    model_name: str,
) -> dict:
    """Train a model, evaluate it, and return metrics."""
    print(f"\n{'='*60}")
    print(f"  🧠 Training {model_name}...")
    print(f"{'='*60}")

    start = time.time()
    model.fit(X_train, y_train)
    train_time = time.time() - start

    y_pred = model.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, average="weighted", zero_division=0)
    rec = recall_score(y_test, y_pred, average="weighted", zero_division=0)
    f1 = f1_score(y_test, y_pred, average="weighted", zero_division=0)
    cm = confusion_matrix(y_test, y_pred)

    print(f"\n  📊 {model_name} Results:")
    print(f"    Accuracy:  {acc:.4f}")
    print(f"    Precision: {prec:.4f}")
    print(f"    Recall:    {rec:.4f}")
    print(f"    F1-Score:  {f1:.4f}")
    print(f"    Train Time: {train_time:.2f}s")
    print(f"\n  Confusion Matrix:")
    print(f"    {cm}")
    print(f"\n  Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["PHISHING", "SAFE"]))

    return {
        "model_name": model_name,
        "model": model,
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1_score": f1,
        "train_time": train_time,
        "confusion_matrix": cm.tolist(),
    }


def main():
    """Main training pipeline."""
    print("\n" + "╔" + "═"*58 + "╗")
    print("║" + "  🛡️  PhishGuard AI — Model Training Pipeline".center(58) + "║")
    print("╚" + "═"*58 + "╝")

    # ── 1. Load dataset ──
    df = load_dataset(DATASET_PATH, MAX_ROWS)

    # ── 2. Extract features ──
    X_df = extract_all_features(df["url"])
    y = df["label"].values

    print(f"\n  Feature matrix shape: {X_df.shape}")
    print(f"  Target vector shape: {y.shape}")

    # ── 3. Scale features ──
    print(f"\n{'='*60}")
    print(f"  📐 Scaling features with StandardScaler...")
    print(f"{'='*60}")

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_df.values)

    # ── 4. Train/test split ──
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )
    print(f"  Train set: {X_train.shape[0]:,} samples")
    print(f"  Test set:  {X_test.shape[0]:,} samples")

    # ── 5. Train models ──
    xgb_model = XGBClassifier(
        n_estimators=300,
        max_depth=8,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        eval_metric="logloss",
        use_label_encoder=False,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )

    rf_model = RandomForestClassifier(
        n_estimators=200,
        max_depth=12,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )

    results = []
    results.append(train_and_evaluate(X_train, X_test, y_train, y_test, xgb_model, "XGBoost"))
    results.append(train_and_evaluate(X_train, X_test, y_train, y_test, rf_model, "RandomForest"))

    # ── 6. Select best model ──
    best = max(results, key=lambda r: r["f1_score"])
    print(f"\n{'='*60}")
    print(f"  🏆 Best Model: {best['model_name']}")
    print(f"    F1-Score: {best['f1_score']:.4f}")
    print(f"    Accuracy: {best['accuracy']:.4f}")
    print(f"{'='*60}")

    # ── 7. Save model and scaler ──
    os.makedirs(os.path.dirname(MODEL_OUTPUT), exist_ok=True)

    joblib.dump(best["model"], MODEL_OUTPUT)
    print(f"  💾 Model saved to: {MODEL_OUTPUT}")

    joblib.dump(scaler, SCALER_OUTPUT)
    print(f"  💾 Scaler saved to: {SCALER_OUTPUT}")

    # ── 8. Save training report ──
    report = {
        "best_model": best["model_name"],
        "metrics": {
            "accuracy": best["accuracy"],
            "precision": best["precision"],
            "recall": best["recall"],
            "f1_score": best["f1_score"],
        },
        "confusion_matrix": best["confusion_matrix"],
        "training_time_seconds": best["train_time"],
        "dataset_size": len(df),
        "feature_count": X_df.shape[1],
        "features": list(X_df.columns),
        "test_size": TEST_SIZE,
    }
    report_path = "app/models/training_report.json"
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"  📄 Training report saved to: {report_path}")

    print(f"\n  ✅ Training pipeline complete!\n")


if __name__ == "__main__":
    main()
