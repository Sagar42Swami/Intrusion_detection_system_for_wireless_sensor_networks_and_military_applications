import argparse
import sys
from pathlib import Path

import joblib
import numpy as np


BASE_DIR = Path(__file__).resolve().parent

ARTIFACTS = {
    "model1": {
        "model": "military_ids_model.pkl",
        "features": "feature_names.pkl",
        "encoder": None,
    },
    "model2": {
        "model": "military_ids_model2.pkl",
        "features": "feature_names2.pkl",
        "encoder": "label_encoder2.pkl",
    },
    "model5": {
        "model": "military_ids_model5.pkl",
        "features": "feature_names5.pkl",
        "encoder": "label_encoder5.pkl",
    },
}


def load_joblib(path: Path):
    try:
        return joblib.load(path)
    except ModuleNotFoundError as exc:
        missing = exc.name or "a required package"
        raise RuntimeError(
            f"Cannot load '{path.name}' because '{missing}' is not installed. "
            f"Install it first, then try again."
        ) from exc


def load_bundle(bundle_name: str):
    if bundle_name not in ARTIFACTS:
        valid = ", ".join(sorted(ARTIFACTS))
        raise ValueError(f"Unknown bundle '{bundle_name}'. Choose one of: {valid}")

    bundle = ARTIFACTS[bundle_name]
    model = load_joblib(BASE_DIR / bundle["model"])
    feature_names = load_joblib(BASE_DIR / bundle["features"])
    encoder = load_joblib(BASE_DIR / bundle["encoder"]) if bundle["encoder"] else None
    return model, feature_names, encoder


def parse_features(raw_pairs, expected_features):
    values = {}
    for item in raw_pairs:
        if "=" not in item:
            raise ValueError(
                f"Invalid feature '{item}'. Use the format feature=value."
            )
        key, raw_value = item.split("=", 1)
        key = key.strip()
        raw_value = raw_value.strip()
        if key not in expected_features:
            raise ValueError(
                f"Unknown feature '{key}'. Expected one of: {', '.join(expected_features)}"
            )
        try:
            values[key] = float(raw_value)
        except ValueError as exc:
            raise ValueError(
                f"Feature '{key}' must be numeric, got '{raw_value}'."
            ) from exc

    missing = [name for name in expected_features if name not in values]
    if missing:
        raise ValueError(
            "Missing required features: " + ", ".join(missing)
        )

    extra = sorted(set(values) - set(expected_features))
    if extra:
        raise ValueError("Unexpected features: " + ", ".join(extra))

    row = np.array([[values[name] for name in expected_features]], dtype=float)
    return row


def decode_prediction(model, encoder, raw_prediction):
    pred_value = raw_prediction[0]
    if encoder is not None:
        pred_value = encoder.inverse_transform([int(pred_value)])[0]
    return pred_value


def decode_probabilities(model, encoder, probabilities):
    if probabilities is None:
        return None

    probs = probabilities[0]
    if encoder is not None and hasattr(encoder, "classes_"):
        labels = list(encoder.classes_)
    elif hasattr(model, "classes_"):
        labels = list(model.classes_)
    else:
        labels = [str(i) for i in range(len(probs))]

    return {
        str(label): float(score)
        for label, score in zip(labels, probs)
    }


def main():
    parser = argparse.ArgumentParser(
        description="Load a saved IDS model bundle and run one prediction safely."
    )
    parser.add_argument(
        "--bundle",
        required=True,
        choices=sorted(ARTIFACTS),
        help="Which saved model bundle to use.",
    )
    parser.add_argument(
        "--feature",
        action="append",
        default=[],
        metavar="NAME=VALUE",
        help="Provide one numeric feature. Repeat for all required features.",
    )
    args = parser.parse_args()

    try:
        model, feature_names, encoder = load_bundle(args.bundle)
        row = parse_features(args.feature, feature_names)
        prediction = model.predict(row)
        probabilities = model.predict_proba(row) if hasattr(model, "predict_proba") else None
        label = decode_prediction(model, encoder, prediction)

        print(f"bundle={args.bundle}")
        print(f"predicted_label={label}")

        decoded_probabilities = decode_probabilities(model, encoder, probabilities)
        if decoded_probabilities:
            print("probabilities=")
            for name, score in sorted(
                decoded_probabilities.items(),
                key=lambda item: item[1],
                reverse=True,
            ):
                print(f"  {name}: {score:.6f}")
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
