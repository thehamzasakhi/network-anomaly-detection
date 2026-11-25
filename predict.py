"""Classify NSL-KDD connection records with the trained Random Forest model.

Input: a CSV in NSL-KDD format with no header (41 features; the trailing
`attack` and `level` columns are optional and ignored if present).

Usage:
    python predict.py records.csv [--model network_anomaly_detection_model.joblib]

Security note: joblib/pickle files can execute code when loaded.
Only load model files from sources you trust.
"""
import argparse

import joblib
import pandas as pd

FEATURES = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
    'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login', 'is_guest_login',
    'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
    'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate',
]
LABELS = {0: 'Normal', 1: 'DoS', 2: 'Probe', 3: 'Privilege', 4: 'Access'}


def build_features(df, model):
    """Reproduce the training-time encoding and align columns to the model."""
    X = pd.get_dummies(df[['protocol_type', 'service']]).join(df.drop(columns=['protocol_type', 'service']))
    # Unseen services become all-zero; columns not used in training are dropped.
    return X.reindex(columns=model.feature_names_in_, fill_value=0)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("csv", help="NSL-KDD formatted records (no header)")
    parser.add_argument("--model", default="network_anomaly_detection_model.joblib")
    args = parser.parse_args()

    model = joblib.load(args.model)
    raw = pd.read_csv(args.csv, header=None)
    df = raw.iloc[:, :len(FEATURES)]
    df.columns = FEATURES

    preds = model.predict(build_features(df, model))
    for i, p in enumerate(preds):
        print(f"record {i}: {LABELS[int(p)]}")
    print("\nsummary:", pd.Series(preds).map(LABELS).value_counts().to_dict())


if __name__ == "__main__":
    main()
