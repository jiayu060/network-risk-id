"""Autoencoder-based anomaly detector using PyTorch."""

import numpy as np

from src.detectors.base import AnomalyDetector


class AutoencoderDetector(AnomalyDetector):
    """Symmetric autoencoder — reconstruction error as anomaly score."""

    def __init__(self, hidden_layers: list = None, latent_dim: int = 8,
                 epochs: int = 50, batch_size: int = 1024,
                 learning_rate: float = 0.001, **kwargs):
        super().__init__(name="autoencoder", weight=kwargs.pop("weight", 1.2))
        self.hidden_layers = hidden_layers or [64, 32, 16, 8, 16, 32, 64]
        self.latent_dim = latent_dim
        self.epochs = epochs
        self.batch_size = batch_size
        self.learning_rate = learning_rate
        self._input_dim: int = None
        self._model = None
        self._threshold: float = 0.0

    def fit(self, X: np.ndarray) -> AnomalyDetector:
        if X.shape[0] < 10:
            return self
        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0).astype(np.float32)

        self._input_dim = X.shape[1]
        self._build_model()

        # Train with early stopping
        import torch
        dataset = torch.tensor(X)
        optimizer = torch.optim.Adam(self._model.parameters(), lr=self.learning_rate)
        loss_fn = torch.nn.MSELoss()

        best_loss = float("inf")
        patience = 5
        patience_counter = 0

        self._model.train()
        n_samples = len(dataset)
        for epoch in range(self.epochs):
            epoch_loss = 0.0
            for i in range(0, n_samples, self.batch_size):
                batch = dataset[i:i + self.batch_size]
                optimizer.zero_grad()
                reconstructed = self._model(batch)
                loss = loss_fn(reconstructed, batch)
                loss.backward()
                optimizer.step()
                epoch_loss += loss.item() * len(batch)

            epoch_loss /= n_samples
            if epoch_loss < best_loss * 0.999:
                best_loss = epoch_loss
                patience_counter = 0
            else:
                patience_counter += 1
            if patience_counter >= patience:
                break

        # Compute threshold from training reconstruction errors
        self._model.eval()
        with torch.no_grad():
            train_errors = []
            for i in range(0, n_samples, self.batch_size):
                batch = dataset[i:i + self.batch_size]
                recon = self._model(batch)
                errors = torch.mean((recon - batch) ** 2, dim=1).numpy()
                train_errors.extend(errors)
        self._threshold = np.percentile(train_errors, 95)

        self._fitted = True
        return self

    def _build_model(self):
        """Build symmetric autoencoder."""
        import torch

        class AutoEncoder(torch.nn.Module):
            def __init__(self, input_dim, hidden_layers):
                super().__init__()
                layers = []
                prev = input_dim
                for units in hidden_layers:
                    layers.append(torch.nn.Linear(prev, units))
                    layers.append(torch.nn.ReLU())
                    prev = units
                layers.pop()  # remove last ReLU
                self.encoder = torch.nn.Sequential(*layers)

                # Decoder: symmetric
                dec_layers = []
                rev = hidden_layers[::-1][1:] + [input_dim]
                for units in rev:
                    dec_layers.append(torch.nn.Linear(prev, units))
                    if units != input_dim:
                        dec_layers.append(torch.nn.ReLU())
                    prev = units
                self.decoder = torch.nn.Sequential(*dec_layers)

            def forward(self, x):
                encoded = self.encoder(x)
                return self.decoder(encoded)

        self._model = AutoEncoder(self._input_dim, self.hidden_layers)

    def score(self, X: np.ndarray) -> np.ndarray:
        if not self._fitted or X.shape[0] == 0:
            return np.zeros(len(X))
        import torch
        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0).astype(np.float32)
        dataset = torch.tensor(X)

        self._model.eval()
        errors = []
        with torch.no_grad():
            for i in range(0, len(dataset), self.batch_size):
                batch = dataset[i:i + self.batch_size]
                recon = self._model(batch)
                err = torch.mean((recon - batch) ** 2, dim=1).numpy()
                errors.extend(err)

        scores = np.array(errors) / max(self._threshold, 1e-10)
        return np.clip(scores, 0, 1)

    def explain(self, X: np.ndarray, indices: np.ndarray = None) -> list:
        """Per-feature reconstruction error."""
        if indices is None:
            scores = self.score(X)
            indices = np.argsort(scores)[-10:]
        import torch
        X_t = torch.tensor(X[indices].astype(np.float32))
        self._model.eval()
        with torch.no_grad():
            recon = self._model(X_t)
            feat_errors = ((recon - X_t) ** 2).numpy()

        explanations = []
        for i, idx in enumerate(indices):
            top_feats = np.argsort(-feat_errors[i])[:5]
            explanations.append({
                "index": int(idx),
                "score": float(feat_errors[i].mean()),
                "top_features": [(int(f), float(feat_errors[i][f])) for f in top_feats],
            })
        return explanations
