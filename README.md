# Network Anomaly Detection with Random Forest (NSL-KDD)

A multi-class network intrusion detector. It sorts each connection record into **Normal** or one of four attack categories, using a scikit-learn Random Forest trained on the [NSL-KDD](https://www.unb.ca/cic/datasets/nsl.html) dataset.

| Class | ID | Example attacks |
|---|---|---|
| Normal | 0 | benign traffic |
| DoS | 1 | `neptune`, `smurf`, `teardrop`, `back` |
| Probe | 2 | `portsweep`, `ipsweep`, `nmap`, `satan` |
| Privilege (U2R) | 3 | `buffer_overflow`, `rootkit`, `perl` |
| Access (R2L) | 4 | `guess_passwd`, `warezclient`, `imap`, `ftp_write` |

## How it works

1. **Data.** Each row describes one network connection with 41 features. These include basic info (duration, protocol, service, bytes sent), content indicators (failed logins, root shell, file creations) and traffic statistics over a time and host window (connection counts, SYN/REJ error rates).
2. **Targets.** Attack names are mapped to the 5 categories above.
3. **Features.** `protocol_type` and `service` are one-hot encoded and joined with 34 numeric features, for **107 inputs** in total.
4. **Split.** 80/20 train/test, then 70/30 train/validation on the training portion (`random_state=1337`).
5. **Model.** `RandomForestClassifier` with default settings (100 trees), saved with `joblib`.

## Results

Held-out test set (29,704 records):

| Class | Precision | Recall | F1 | Support |
|---|---|---|---|---|
| Normal | 0.99 | 1.00 | 1.00 | 15,402 |
| DoS | 1.00 | 1.00 | 1.00 | 10,721 |
| Probe | 0.99 | 1.00 | 1.00 | 2,796 |
| Privilege | 0.62 | 0.24 | 0.34 | 21 |
| Access | 0.96 | 0.92 | 0.94 | 764 |
| **Accuracy** | | | **0.9949** | 29,704 |

Macro F1 is **0.85**. The headline accuracy is driven by the large classes. The Privilege class has very few samples, and its recall is poor.

## Repository layout

```
├── network-anomaly-detection.ipynb   # full pipeline: load → encode → split → train → evaluate → save
├── predict.py                        # CLI: classify NSL-KDD records with the trained model
├── requirements.txt
└── README.md
```

## Setup

```bash
git clone https://github.com/thehamzasakhi/network-anomaly-detection.git
cd network-anomaly-detection
python -m venv .venv && source .venv/bin/activate   # or use conda
pip install -r requirements.txt
```

### Dataset

Download `KDDTrain+.txt` and `KDDTest+.txt` from the [NSL-KDD page](https://www.unb.ca/cic/datasets/nsl.html) and combine them into the single file the notebook expects:

```bash
cat KDDTrain+.txt KDDTest+.txt > KDD+.txt   # 125,973 + 22,544 = 148,517 rows
```

## Usage

### Train

```bash
jupyter notebook network-anomaly-detection.ipynb
```

Running all cells saves `network_anomaly_detection_model.joblib`.

### Use the pre-trained model

Download `network_anomaly_detection_model.joblib` (≈21 MB) from the [Releases](../../releases) page. Then pass it a CSV of NSL-KDD-formatted records without a header row. Trailing label columns are ignored.

```bash
python predict.py records.csv
```

```
record 0: Normal
record 1: Normal
record 2: DoS
record 3: Probe
record 4: Access

summary: {'Normal': 2, 'DoS': 1, 'Probe': 1, 'Access': 1}
```

> ⚠️ `joblib` files are pickles and can execute code when loaded. Only load model files from sources you trust.

The model was trained with scikit-learn 1.9.1. Loading it with a much older or newer version may print a warning or fail. If that happens, retrain with the notebook.

## Known issues

These are kept as-is so the notebook matches the released model.

- **Label-name mismatches in the category lists.** Three names don't match the names used in the dataset, so those attacks fall through to **Normal (0)**: 153 records in total.

  | In code | In dataset | Records |
  |---|---|---|
  | `loadmdoule` | `loadmodule` | 11 (Privilege) |
  | `http_tunnel` | `httptunnel` | 133 (Access) |
  | `xclock` | `xlock` | 9 (Access) |

  Fix these names before retraining, and it's best to raise an error for any unmapped label rather than silently defaulting to Normal.
- **Optimistic evaluation.** `KDD+.txt` merges the official train and test files and is then split randomly. NSL-KDD's official `KDDTest+` deliberately contains attack types that are absent from training. Train on `KDDTrain+` and evaluate on `KDDTest+` for a realistic estimate of how the model handles novel attacks.
- **Unused features.** `flag` (TCP connection status), `land`, `logged_in`, `is_host_login` and `is_guest_login` are not used. `num_outbound_cmds` is always 0 and carries no information.

## Ideas for improvement

- **Class imbalance:** try `class_weight='balanced'`, oversampling (e.g. SMOTE) or merging rare classes for U2R/R2L.
- **Better metrics:** report macro-F1 and per-class recall, which matter more for rare attacks than overall accuracy.
- **Tuning:** add hyperparameter search (`n_estimators`, `max_depth`, `min_samples_leaf`) using the validation split.
- **Reusable preprocessing:** wrap the encoding and the model in a scikit-learn `Pipeline` with `OneHotEncoder(handle_unknown='ignore')`, so it applies consistently at inference time.

## References

- M. Tavallaee, E. Bagheri, W. Lu, A. A. Ghorbani. *A Detailed Analysis of the KDD CUP 99 Data Set*. IEEE CISDA 2009.
- L. Breiman. *Random Forests*. Machine Learning, 45(1), 2001.

## Disclaimer

For research and educational purposes only. This is a learning project and not a production intrusion-detection system.
