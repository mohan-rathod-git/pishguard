"""
PhishGuard AI — CLI Testing Script
Test the prediction engine directly from the command line.

Usage:
    python -m app.training.cli_test
    python -m app.training.cli_test --url "https://suspicious-site.xyz/login"
    python -m app.training.cli_test --batch
"""

import argparse
import json
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from app.ml.predictor import predictor
from app.utils.feature_extractor import extract_features


# ── Test URLs ──
TEST_URLS = [
    # Likely SAFE
    "https://www.google.com",
    "https://github.com/trending",
    "https://stackoverflow.com/questions",
    "https://www.wikipedia.org",
    "https://www.amazon.com/dp/B08N5WRWNW",

    # Likely PHISHING
    "http://192.168.1.1/login/verify-account.php",
    "http://secure-paypal-login.suspicious-domain.xyz/signin",
    "http://apple-id-verify-account.tk/restore",
    "http://microsoft-security-alert.club/update-password",
    "http://free-gift-winner-claim.top/reward",

    # Likely SPAM/SCAM
    "http://bit.ly/3xAbCd",
    "http://free-bitcoin-prize-winner.buzz/claim-now",
    "http://172.16.0.1:8080/admin/exec?cmd=rm",

    # Edge cases
    "https://xn--80ak6aa92e.com",  # Punycode
    "ftp://files.example.com/download.exe",
]


def print_result(result: dict) -> None:
    """Pretty-print a single prediction result."""
    pred = result["prediction"]

    # Color codes
    colors = {
        "SAFE": "\033[92m",       # green
        "PHISHING": "\033[91m",   # red
        "MALWARE": "\033[95m",    # magenta
        "SPAM": "\033[93m",       # yellow
        "SCAM": "\033[93m",       # yellow
        "ERROR": "\033[90m",      # grey
    }
    reset = "\033[0m"
    color = colors.get(pred, "\033[0m")

    print(f"\n{'─'*60}")
    print(f"  URL:        {result['url'][:70]}")
    print(f"  Prediction: {color}{pred}{reset}")
    print(f"  Confidence: {result['confidence']:.2%}")
    print(f"  Risk Score: {result['risk_score']}/100")
    print(f"  Reasons:")
    for reason in result["reasons"]:
        icon = "⚠️" if "risk" not in reason.lower() else "🔍"
        print(f"    {icon} {reason}")


def main():
    parser = argparse.ArgumentParser(description="PhishGuard AI — CLI Tester")
    parser.add_argument("--url", type=str, help="Single URL to test")
    parser.add_argument("--batch", action="store_true", help="Run batch test with built-in URLs")
    parser.add_argument("--features", type=str, help="Show extracted features for a URL")
    args = parser.parse_args()

    # Load model
    print("\n🛡️  PhishGuard AI — CLI Test Tool")
    print("=" * 60)

    loaded = predictor.load_model()
    if not loaded:
        print("\n❌ No trained model found!")
        print("   Run: python -m app.training.train_model")
        sys.exit(1)

    info = predictor.get_model_info()
    print(f"  Model: {info.get('model_type', 'Unknown')}")
    print(f"  Version: {info.get('model_version', 'Unknown')}")
    print(f"  Features: {info.get('feature_count', 0)}")

    if args.features:
        print(f"\n📊 Features for: {args.features}")
        feats = extract_features(args.features)
        for k, v in feats.items():
            print(f"  {k:.<35} {v}")
        return

    if args.url:
        result = predictor.predict_url(args.url)
        print_result(result)
        return

    # Default: batch test
    print(f"\n🔬 Running batch test with {len(TEST_URLS)} URLs...")

    results = predictor.predict_batch(TEST_URLS)

    # Summary
    summary = {}
    for r in results:
        print_result(r)
        summary[r["prediction"]] = summary.get(r["prediction"], 0) + 1

    print(f"\n{'='*60}")
    print(f"  📊 Summary:")
    for label, count in sorted(summary.items()):
        print(f"    {label}: {count}")
    print(f"  Total: {len(results)}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
