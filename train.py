from pathlib import Path
from urllib.parse import urlsplit
import ipaddress
import json
import random

import joblib
import pandas as pd

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import Pipeline

from url_features import normalize_for_model


BASE_DIR = Path(__file__).resolve().parent
DATA_PATH = BASE_DIR / "data" / "urls.csv"
MODEL_DIR = BASE_DIR / "model"
MODEL_PATH = MODEL_DIR / "url_model.joblib"
METRICS_PATH = MODEL_DIR / "metrics.json"


def get_host(value):
    """Extract a hostname for grouping related URLs."""
    try:
        parsed = urlsplit(str(value).strip())
        host = (parsed.hostname or "").lower()

        # Group www.example.com with example.com to prevent leakage.
        if host.startswith("www."):
            host = host[4:]

        return host
    except (ValueError, TypeError):
        return ""


def main():
    if not DATA_PATH.exists():
        raise SystemExit(f"Dataset not found: {DATA_PATH}")

    print("Loading dataset...")

    df = pd.read_csv(
        DATA_PATH,
        usecols=["URL", "label"],
        low_memory=False,
    )

    df = df.dropna(subset=["URL", "label"]).copy()
    df["URL"] = df["URL"].astype(str).str.strip()

    label_map = {
        1: "benign",
        0: "phishing",
        "1": "benign",
        "0": "phishing",
        "benign": "benign",
        "phishing": "phishing",
    }

    df["label"] = df["label"].map(
        lambda value: label_map.get(
            value,
            label_map.get(str(value).strip().lower()),
        )
    )

    df = df.dropna(subset=["label"])
    df = df[df["URL"] != ""].copy()

    # Normalize using exactly the same canonical function as inference (stripping www. artifact)
    print("Normalizing URLs...")
    df["model_url"] = df["URL"].map(normalize_for_model)
    df = df[df["model_url"] != ""].copy()

    # Remove normalized URLs that have contradictory labels.
    label_counts = df.groupby("model_url")["label"].nunique()
    conflicting_urls = set(label_counts[label_counts > 1].index)

    print(f"Conflicting normalized URLs excluded: {len(conflicting_urls)}")

    df = df[~df["model_url"].isin(conflicting_urls)].copy()

    # Remove repeated normalized URLs with the same label.
    df = df.drop_duplicates(subset=["model_url"]).reset_index(drop=True)

    if df["label"].nunique() != 2:
        raise SystemExit("Both benign and phishing classes are required.")

    df["group"] = df["URL"].map(get_host)

    # URLs without a hostname cannot be reliably grouped.
    df = df[df["group"] != ""].reset_index(drop=True)

    if df["group"].nunique() < 2:
        raise SystemExit("Not enough distinct hostnames to split the dataset.")

    print(f"Usable unique URLs: {len(df):,}")
    print("\nLabel counts:")
    print(df["label"].value_counts().to_string())

    # Keep hostnames completely separate between train and test.
    splitter = GroupShuffleSplit(
        n_splits=1,
        test_size=0.20,
        random_state=42,
    )

    train_idx, test_idx = next(
        splitter.split(
            df["model_url"],
            df["label"],
            groups=df["group"],
        )
    )

    train_df = df.iloc[train_idx].copy()
    test_df = df.iloc[test_idx].copy()

    overlap = set(train_df["group"]) & set(test_df["group"])

    if overlap:
        raise SystemExit("Hostname leakage detected.")

    if train_df["label"].nunique() != 2:
        raise SystemExit(
            "Training split contains only one class. "
            "Try another split seed."
        )

    if test_df["label"].nunique() != 2:
        raise SystemExit(
            "Test split contains only one class. "
            "Try another split seed."
        )

    # Augment benign training set with realistic web paths to avoid synthetic path bias
    common_paths = [
        "/about", "/contact", "/privacy", "/terms", "/help", "/faq",
        "/products", "/services", "/blog", "/news", "/docs", "/login",
        "/index.html", "/support", "/search?q=info", "/pricing", "/home"
    ]
    rng = random.Random(42)
    benign_aug = []
    for row in train_df[train_df["label"] == "benign"].itertuples():
        if rng.random() < 0.30:
            p = rng.choice(common_paths)
            augmented_url = row.model_url.rstrip("/") + p
            benign_aug.append({
                "model_url": augmented_url,
                "label": "benign",
                "group": row.group
            })

    if benign_aug:
        aug_df = pd.DataFrame(benign_aug)
        train_df = pd.concat([train_df, aug_df], ignore_index=True)
        print(f"Augmented benign training samples with paths: {len(benign_aug):,}")

    print(f"\nTraining rows: {len(train_df):,}")
    print(f"Test rows: {len(test_df):,}")
    print(f"Training hostnames: {train_df['group'].nunique():,}")
    print(f"Test hostnames: {test_df['group'].nunique():,}")
    print(f"Hostname overlap: {len(overlap)}")

    pipeline = Pipeline([
        (
            "tfidf",
            TfidfVectorizer(
                analyzer="char",
                ngram_range=(3, 5),
                min_df=3,
                max_features=250_000,
                sublinear_tf=True,
            ),
        ),
        (
            "classifier",
            LogisticRegression(
                max_iter=1500,
                class_weight="balanced",
                C=1.2,
                random_state=42,
            ),
        ),
    ])

    print("\nTraining model...")
    pipeline.fit(train_df["model_url"], train_df["label"])

    predictions = pipeline.predict(test_df["model_url"])
    y_true = test_df["label"]

    labels = ["benign", "phishing"]
    matrix = confusion_matrix(y_true, predictions, labels=labels)
    tn, fp, fn, tp = matrix.ravel()

    metrics = {
        "split_method": "GroupShuffleSplit by hostname",
        "train_rows": int(len(train_df)),
        "test_rows": int(len(test_df)),
        "train_hostnames": int(train_df["group"].nunique()),
        "test_hostnames": int(test_df["group"].nunique()),
        "hostname_overlap": len(overlap),
        "conflicting_urls_excluded": len(conflicting_urls),
        "accuracy": float(accuracy_score(y_true, predictions)),
        "phishing_precision": float(
            precision_score(
                y_true, predictions,
                pos_label="phishing",
                zero_division=0,
            )
        ),
        "phishing_recall": float(
            recall_score(
                y_true, predictions,
                pos_label="phishing",
                zero_division=0,
            )
        ),
        "phishing_f1": float(
            f1_score(
                y_true, predictions,
                pos_label="phishing",
                zero_division=0,
            )
        ),
        "benign_false_positive_rate": float(
            fp / (fp + tn) if (fp + tn) else 0.0
        ),
        "confusion_matrix_labels": labels,
        "confusion_matrix": matrix.tolist(),
        "classification_report": classification_report(
            y_true,
            predictions,
            labels=labels,
            output_dict=True,
            zero_division=0,
        ),
    }

    print("\n=== DOMAIN-GROUPED TEST RESULTS ===")
    print(f"Accuracy: {metrics['accuracy']:.4f}")
    print(f"Phishing precision: {metrics['phishing_precision']:.4f}")
    print(f"Phishing recall: {metrics['phishing_recall']:.4f}")
    print(f"Phishing F1: {metrics['phishing_f1']:.4f}")
    print(
        "Benign false-positive rate: "
        f"{metrics['benign_false_positive_rate']:.4f}"
    )

    print("\nConfusion matrix (rows=actual, columns=predicted):")
    print("Labels:", labels)
    print(matrix)

    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    bundle = {
        "pipeline": pipeline,
        "model_name": "Normalized Canonical URL TF-IDF + Logistic Regression",
        "positive_label": "phishing",
        "training_rows": int(len(train_df)),
        "normalization": "url_features.normalize_for_model",
    }

    joblib.dump(bundle, MODEL_PATH)

    with METRICS_PATH.open("w", encoding="utf-8") as file:
        json.dump(metrics, file, indent=2)

    print(f"\nModel saved: {MODEL_PATH}")
    print(f"Metrics saved: {METRICS_PATH}")


if __name__ == "__main__":
    main()
