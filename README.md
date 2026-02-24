# Project O3: Secure AI Chat Assistant

A secure, privacy-first AI chat interface built with FastAPI, Ollama (Llama 3.1), and Google Gemini. This project automatically detects and masks Sensitive Personally Identifiable Information (PII) before sending prompts to external cloud LLMs.

## Features

- **Local Privacy Layer**: Uses a locally-hosted LLM (Llama 3.1 via Ollama) and Regex to comprehensively detect and categorize sensitive data (Emails, Passwords, API Keys, Credit Cards, etc.).
- **Data Masking**: Automatically replaces detected PII with secure placeholders (e.g., `<<EMAIL_1>>`) before any data leaves your machine.
- **Cloud Intelligence**: securely proxies the sanitized queries to Google's Gemini 2.5 Flash for high-quality responses.
- **Auto-Unmasking**: Seamlessly unmasks the response so the user sees the original context without ever exposing the raw sensitive data to the cloud.
- **Modern UI**: A sleek, dark-themed responsive user interface inspired by modern AI apps.

## Prerequisites

- Python 3.9+
- [Ollama](https://ollama.com/) installed and running locally with the `llama3.1:8b` model (`ollama run llama3.1:8b`)
- A Google Gemini API Key

## Setup

1. **Clone the repository:**
   ```bash
   git clone <your-repository-url>
   cd O3
   ```

2. **Create a virtual environment (recommended):**
   ```bash
   python -m venv .venv
   # Windows
   .\.venv\Scripts\activate
   # macOS/Linux
   source .venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Environment Variables:**
   Create a `config.py` file in the root directory (or set it in your environment) with your API key:
   ```python
   # config.py
   GEMINI_API_KEY = "your_actual_api_key_here"
   ```
   *(Note: `config.py` is ignored by git to protect your keys)*

## Running the Application

Start the FastAPI server:
```bash
python main.py
```
Or run directly with uvicorn:
```bash
uvicorn main:app --reload
```

The application will be available at [http://127.0.0.1:8000](http://127.0.0.1:8000)
