Place your GCP service account key JSON here as:

- `secrets/gcp-sa.json`

This file is mounted read-only into the Airflow and API containers at `/secrets/gcp-sa.json` and used via `GOOGLE_APPLICATION_CREDENTIALS`.

