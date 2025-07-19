# InstaReportBot: CLI Automation Learning Project

This project is a **strictly educational and experimental** Python CLI tool designed to explore automation patterns, secure configuration management, and responsible API interaction. It is built to operate **only on Instagram accounts you own and control**, and explicitly includes safeguards to prevent misuse.

**Purpose:**
- To demonstrate Python CLI development with `argparse`.
- To learn secure handling of sensitive configurations using `cryptography.fernet`.
- To implement robust logging with `logging` and `rich`.
- To explore `instagrapi` for interacting with the Instagram API responsibly.
- To understand retry mechanisms and randomized back-off for network operations.
- To implement permission enforcement and dry-run modes for safety.

**Disclaimer:**
This tool is for **educational use only**. Do not use it to target real Instagram accounts that you do not own or have explicit, documented permission to interact with in this manner. Misuse of automation tools can violate Instagram's Terms of Service and lead to account suspension or other penalties. The "reporting" functionality is heavily simulated in dry-run mode and, in live mode, is a placeholder for `instagrapi`'s actual methods, which should only be used in compliance with platform policies and explicit permissions.

---

### Setup and Installation

1.  **Clone the repository (or create the files manually):**
    ```bash
    git clone <your-repo-url>
    cd insta_automation_project
    ```

2.  **Create a Python Virtual Environment (recommended):**
    ```bash
    python3 -m venv venv
    source venv/bin/activate # On Windows: .\venv\Scripts\activate
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

---

### Authorization Workflow & Configuration

The tool requires a secure `config.json.encrypted` file, which stores sensitive settings like your bot access password hash, expiry date, and authorized users.

#### 1. Initialize the Configuration:

Run the `--init` command. This will prompt you for necessary details and create `secret.key` and `config.json.encrypted`.

```bash
python instabot_cli.py --init
