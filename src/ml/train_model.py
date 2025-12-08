import os
import argparse
import json
from typing import Tuple
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import torch
from torch import nn
from torch.utils.data import Dataset, DataLoader

#!/usr/bin/env python3
"""
train_model.py

Train a simple feed-forward NN on UNSW NB15 CSV data using PyTorch.

Usage:
    python train_model.py --csv /path/to/UNSW_NB15.csv --outdir ./models --epochs 30

Notes:
- Expects a CSV with a label column named 'label' (0/1) or 'attack_cat' (strings) / 'label' (multiclass ints).
- Automatically handles numeric/categorical features, missing values, and scaling.
- Saves best model and scaler/metadata to outdir.
"""




# -----------------------
# Dataset and utilities
# -----------------------
class TabularDataset(Dataset):
    def __init__(self, X: np.ndarray, y: np.ndarray):
        self.X = torch.from_numpy(X).float()
        if y is None:
            self.y = None
        else:
            # y may be int (multiclass) or float (binary)
            if np.issubdtype(y.dtype, np.floating):
                self.y = torch.from_numpy(y).float().unsqueeze(1)
            else:
                # multiclass: long tensor
                self.y = torch.from_numpy(y).long()
    def __len__(self):
        return len(self.X)
    def __getitem__(self, idx):
        if self.y is None:
            return self.X[idx]
        return self.X[idx], self.y[idx]

def load_and_preprocess(csv_path: str, label_cols=None, test_size=0.2, val_size=0.1, random_state=42):
    df = pd.read_csv(csv_path)
    # Identify label column
    label_col = None
    candidates = label_cols or ['label', 'attack_cat', 'attack', 'class']
    for c in candidates:
        if c in df.columns:
            label_col = c
            break
    if label_col is None:
        raise ValueError(f"Could not find label column. Expected one of {candidates}")

    y_raw = df[label_col].copy()
    X_df = df.drop(columns=[label_col])

    # Drop obvious non-feature columns (timestamps, ids)
    drop_candidates = [c for c in X_df.columns if c.lower() in ('id', 'timestamp', 'ts', 'dur', 'date')]
    if drop_candidates:
        X_df = X_df.drop(columns=drop_candidates, errors='ignore')

    # Handle categorical columns: factorize (simple)
    for col in X_df.columns:
        if X_df[col].dtype == object or pd.api.types.is_categorical_dtype(X_df[col]):
            X_df[col], _ = pd.factorize(X_df[col], sort=True)
    # Fill missing numeric values
    X_df = X_df.fillna(X_df.median(numeric_only=True))

    # Process labels:
    # If label is textual categories (attack types), convert to ints (multiclass).
    if y_raw.dtype == object or pd.api.types.is_categorical_dtype(y_raw):
        y, uniques = pd.factorize(y_raw, sort=True)
        is_multiclass = True
    else:
        # numeric labels: check unique count
        uniques = np.unique(y_raw.values)
        if len(uniques) == 2 and set(uniques) <= {0, 1}:
            # binary
            y = y_raw.astype(int).values
            is_multiclass = False
        else:
            # treat as multiclass
            y = y_raw.astype(int).values
            is_multiclass = True

    X = X_df.values.astype(np.float32)

    # Split train/val/test
    X_train, X_tmp, y_train, y_tmp = train_test_split(X, y, test_size=test_size + val_size, random_state=random_state, stratify=y if len(np.unique(y))>1 else None)
    val_rel = val_size / (test_size + val_size)
    X_val, X_test, y_val, y_test = train_test_split(X_tmp, y_tmp, test_size=val_rel, random_state=random_state, stratify=y_tmp if len(np.unique(y_tmp))>1 else None)

    # Scale (fit on train)
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_val = scaler.transform(X_val)
    X_test = scaler.transform(X_test)

    meta = {
        'feature_names': list(X_df.columns),
        'label_column': label_col,
        'is_multiclass': bool(is_multiclass),
        'classes': [str(x) for x in (uniques.tolist() if hasattr(uniques, 'tolist') else list(np.unique(y)))]
    }

    return (X_train, y_train), (X_val, y_val), (X_test, y_test), scaler, meta

# -----------------------
# Model
# -----------------------
class MLP(nn.Module):
    def __init__(self, input_dim: int, hidden_dims=(128,64), dropout=0.2, num_classes=1, multiclass=False):
        super().__init__()
        layers = []
        prev = input_dim
        for h in hidden_dims:
            layers.append(nn.Linear(prev, h))
            layers.append(nn.BatchNorm1d(h))
            layers.append(nn.ReLU(inplace=True))
            layers.append(nn.Dropout(dropout))
            prev = h
        if multiclass:
            layers.append(nn.Linear(prev, num_classes))
        else:
            layers.append(nn.Linear(prev, 1))  # binary logit
        self.net = nn.Sequential(*layers)
    def forward(self, x):
        return self.net(x)

# -----------------------
# Training loop
# -----------------------
def train(csv_path: str, outdir: str, epochs=20, batch_size=256, lr=1e-3, hidden="128,64", dropout=0.2, device=None):
    device = device or ("cuda" if torch.cuda.is_available() else "cpu")
    os.makedirs(outdir, exist_ok=True)

    (X_train, y_train), (X_val, y_val), (X_test, y_test), scaler, meta = load_and_preprocess(csv_path)

    multiclass = meta['is_multiclass']
    num_classes = len(meta['classes']) if multiclass else 1

    train_ds = TabularDataset(X_train, y_train)
    val_ds = TabularDataset(X_val, y_val)
    test_ds = TabularDataset(X_test, y_test)

    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True, num_workers=2, pin_memory=True)
    val_loader = DataLoader(val_ds, batch_size=batch_size, shuffle=False, num_workers=2, pin_memory=True)
    test_loader = DataLoader(test_ds, batch_size=batch_size, shuffle=False, num_workers=2, pin_memory=True)

    hidden_dims = tuple(int(x) for x in hidden.split(',')) if isinstance(hidden, str) else tuple(hidden)
    model = MLP(input_dim=X_train.shape[1], hidden_dims=hidden_dims, dropout=dropout, num_classes=num_classes, multiclass=multiclass)
    model.to(device)

    if multiclass:
        criterion = nn.CrossEntropyLoss()
    else:
        criterion = nn.BCEWithLogitsLoss()

    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    best_val_metric = -1.0
    best_path = os.path.join(outdir, "best_model.pt")

    for epoch in range(1, epochs+1):
        model.train()
        running_loss = 0.0
        for xb, yb in train_loader:
            xb = xb.to(device)
            yb = yb.to(device)
            optimizer.zero_grad()
            logits = model(xb)
            if multiclass:
                loss = criterion(logits, yb)
            else:
                loss = criterion(logits, yb.float().unsqueeze(1))
            loss.backward()
            optimizer.step()
            running_loss += loss.item() * xb.size(0)
        avg_loss = running_loss / len(train_loader.dataset)

        val_loss, val_acc = evaluate(model, val_loader, criterion, device, multiclass)
        print(f"Epoch {epoch:3d} | Train Loss: {avg_loss:.4f} | Val Loss: {val_loss:.4f} | Val Acc: {val_acc:.4f}")

        # Save best by val_acc
        if val_acc > best_val_metric:
            best_val_metric = val_acc
            torch.save({'model_state_dict': model.state_dict(),
                        'meta': meta,
                        'scaler_mean': scaler.mean_.tolist(),
                        'scaler_var': scaler.var_.tolist(),
                        'scaler_scale': scaler.scale_.tolist(),
                        'input_dim': X_train.shape[1]}, best_path)

    # Final test evaluation
    checkpoint = torch.load(best_path, map_location=device)
    model.load_state_dict(checkpoint['model_state_dict'])
    test_loss, test_acc = evaluate(model, test_loader, criterion, device, multiclass)
    print(f"Test Loss: {test_loss:.4f} | Test Acc: {test_acc:.4f}")
    # Save metadata
    with open(os.path.join(outdir, "meta.json"), "w") as f:
        json.dump(meta, f, indent=2)
    print(f"Best model saved to: {best_path}")

def evaluate(model, loader, criterion, device, multiclass=False) -> Tuple[float, float]:
    model.eval()
    total_loss = 0.0
    correct = 0
    total = 0
    with torch.no_grad():
        for xb, yb in loader:
            xb = xb.to(device)
            yb = yb.to(device)
            logits = model(xb)
            if multiclass:
                loss = criterion(logits, yb)
                preds = torch.argmax(logits, dim=1)
                correct += (preds == yb).sum().item()
                total += yb.size(0)
            else:
                loss = criterion(logits, yb.float().unsqueeze(1))
                probs = torch.sigmoid(logits).squeeze(1)
                preds = (probs >= 0.5).long()
                correct += (preds == yb).sum().item()
                total += yb.size(0)
            total_loss += loss.item() * xb.size(0)
    avg_loss = total_loss / len(loader.dataset)
    acc = correct / total if total > 0 else 0.0
    return avg_loss, acc

# -----------------------
# CLI
# -----------------------
def parse_args():
    p = argparse.ArgumentParser(description="Train NN on UNSW NB15 CSV")
    p.add_argument('--csv', type=str, required=True, help="Path to UNSW NB15 CSV file")
    p.add_argument('--outdir', type=str, default='./models', help="Directory to save model and metadata")
    p.add_argument('--epochs', type=int, default=20)
    p.add_argument('--batch-size', type=int, default=256)
    p.add_argument('--lr', type=float, default=1e-3)
    p.add_argument('--hidden', type=str, default='128,64', help="Comma-separated hidden layer sizes")
    p.add_argument('--dropout', type=float, default=0.2)
    return p.parse_args()

if __name__ == "__main__":
    args = parse_args()
    train(csv_path=args.csv, outdir=args.outdir, epochs=args.epochs, batch_size=args.batch_size,
          lr=args.lr, hidden=args.hidden, dropout=args.dropout)