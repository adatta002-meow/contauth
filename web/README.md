# ContAuth web version

A browser-run version of the system, published at https://claude.ai/artifact/KAb1aZAwSASBqGaHgyrKzj
(Claude artifact with shared storage).

- `index.html`: capture, the 21 features, the Zero Trust engine, personal Isolation Forest with
  per-user threshold calibration, accounts, notes, protected settings, admin dashboard.
- `population.json`: the server's trained population Isolation Forest (`models/population.joblib`),
  exported tree by tree. Its scores match scikit-learn to 6 decimal places.

Differences from the Flask server: enforcement runs in each visitor's browser, personal profiles use
an Isolation Forest only (no One-Class SVM or supervised model), and network changes are simulated.
