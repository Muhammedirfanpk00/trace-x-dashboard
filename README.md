# TRACE-X Dashboard Website

## Run locally
1. Install Python 3.10+.
2. Open a terminal in this folder.
3. Run: `pip install -r requirements.txt`
4. Run: `streamlit run app.py`

The `data/` folder contains the supplied CSV files.

## Publish online with Streamlit Community Cloud
1. Create/sign in to GitHub.
2. Create a new repository, e.g. `trace-x-dashboard`.
3. Upload `app.py`, `requirements.txt`, and the whole `data/` folder.
4. Go to https://share.streamlit.io/ and connect GitHub.
5. Choose your repository, branch (usually `main`), and main file path `app.py`.
6. Deploy. The service will provide a shareable website URL.

Note: The app uses the provided synthetic demo data. Keep the app's warning language: review priorities and model probabilities are indicators, not proof of an attack.
