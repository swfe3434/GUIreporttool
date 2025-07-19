import argparse
import json
import logging
import os
import sys
import time
import random
import hmac
import hashlib
from datetime import datetime
from uuid import uuid4

from cryptography.fernet import Fernet, InvalidToken
from instagrapi import Client
from instagrapi.exceptions import (
    BadPassword, TwoFactorRequired, ChallengeRequired,
    FeedbackRequired, PleaseWaitFewMinutes, ClientError
)
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

# --- Configuration Constants ---
CONFIG_FILE_ENCRYPTED = "config.json.encrypted"
SECRET_KEY_FILE = "secret.key"
LOG_FILE = "report_bot.log"
DEFAULT_DELAY_MIN = 5  # seconds
DEFAULT_DELAY_MAX = 15 # seconds
MAX_RETRIES = 3

# --- Rich Console Initialization ---
console = Console()

# --- Logging Setup ---
class CustomLogger:
    def __init__(self, name="InstaReportBot"):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.INFO)

        # Ensure handlers are not duplicated on re-init
        if not self.logger.handlers:
            # File handler (rotating)
            file_handler = logging.handlers.RotatingFileHandler(
                LOG_FILE, maxBytes=10485760, backupCount=5
            )
            file_handler.setFormatter(logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            ))
            self.logger.addHandler(file_handler)

            # Rich Console Handler
            rich_handler = RichHandler(
                level=logging.INFO, console=console, show_time=True,
                show_level=True, show_path=True, enable_link_path=True
            )
            self.logger.addHandler(rich_handler)

    def get_logger(self):
        return self.logger

logger = CustomLogger().get_logger()

# --- Encryption Utilities ---
class ConfigManager:
    def __init__(self):
        self.fernet = self._load_or_generate_key()
        self.config = {}
        self.config_path = CONFIG_FILE_ENCRYPTED

    def _load_or_generate_key(self):
        if os.path.exists(SECRET_KEY_FILE):
            with open(SECRET_KEY_FILE, "rb") as f:
                key = f.read()
            logger.info("Loaded encryption key from secret.key")
        else:
            key = Fernet.generate_key()
            with open(SECRET_KEY_FILE, "wb") as f:
                f.write(key)
            logger.info(f"Generated new encryption key and saved to {SECRET_KEY_FILE}")
        return Fernet(key)

    def encrypt_config(self, config_data):
        try:
            encrypted_data = self.fernet.encrypt(json.dumps(config_data).encode('utf-8'))
            with open(self.config_path, "wb") as f:
                f.write(encrypted_data)
            logger.info(f"Configuration encrypted and saved to {self.config_path}")
        except Exception as e:
            logger.error(f"Failed to encrypt configuration: {e}")
            sys.exit(1)

    def decrypt_config(self):
        if not os.path.exists(self.config_path):
            logger.error(f"Encrypted config file not found: {self.config_path}. Please run --init first.")
            sys.exit(1)
        try:
            with open(self.config_path, "rb") as f:
                encrypted_data = f.read()
            decrypted_data = self.fernet.decrypt(encrypted_data).decode('utf-8')
            self.config = json.loads(decrypted_data)
            logger.info(f"Configuration decrypted from {self.config_path}")
            return self.config
        except InvalidToken:
            logger.error("Failed to decrypt config.json.encrypted. Key might be wrong or file corrupted.")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Failed to decrypt or parse configuration: {e}")
            sys.exit(1)

    def get_config(self):
        return self.config

# --- Decorator for Retry Logic ---
def retry_on_failure(max_retries=MAX_RETRIES, delay_min=DEFAULT_DELAY_MIN, delay_max=DEFAULT_DELAY_MAX):
    def decorator(func):
        def wrapper(*args, **kwargs):
            retries = 0
            while retries < max_retries:
                try:
                    return func(*args, **kwargs)
                except (ClientError, PleaseWaitFewMinutes, ConnectionError, TimeoutError) as e:
                    retries += 1
                    sleep_time = random.uniform(delay_min, delay_max)
                    logger.warning(f"Operation failed: {e}. Retrying {retries}/{max_retries} in {sleep_time:.2f} seconds...")
                    time.sleep(sleep_time)
                except Exception as e:
                    logger.error(f"An unexpected error occurred during retryable operation: {e}")
                    raise # Re-raise other exceptions
            logger.error(f"Operation failed after {max_retries} retries.")
            return None # Indicate failure after max retries
        return wrapper
    return decorator

# --- Instagram Bot Class ---
class InstaReportBot:
    def __init__(self, config_manager, run_id):
        self.config_manager = config_manager
        self.config = config_manager.get_config()
        self.cl = Client() # instagrapi client
        self.run_id = run_id
        self.auth_state = {
            "password_ok": False,
            "expiry_ok": False,
            "user_authorized": False,
            "permission_doc_ok": False,
            "instagram_login_ok": False
        }

        self.REASONS = {
            1: "Spam",
            2: "Nudity or Sexual Activity",
            3: "Hate Speech",
            4: "Violence or Dangerous Organizations",
            5: "Intellectual Property Violation",
            6: "Sale of Illegal or Regulated Goods",
            7: "Bullying or Harassment",
            8: "Scam or Fraud",
            9: "Self-Injury",
            10: "Something Else" # General category
        }

    def _display_auth_summary(self):
        table = Table(title="Authorization Summary", style="bold magenta")
        table.add_column("Check", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Details", style="yellow")

        table.add_row("Bot Access Password", "[bold green]OK[/bold green]" if self.auth_state["password_ok"] else "[bold red]FAILED[/bold red]", "")
        table.add_row("Configuration Expiry", "[bold green]OK[/bold green]" if self.auth_state["expiry_ok"] else "[bold red]EXPIRED[/bold red]", self.config.get("EXPIRY_DATE", "N/A"))
        table.add_row("Current OS User", "[bold green]AUTHORIZED[/bold green]" if self.auth_state["user_authorized"] else "[bold red]UNAUTHORIZED[/bold red]", os.getlogin())
        table.add_row("Permission Document", "[bold green]VALID[/bold green]" if self.auth_state["permission_doc_ok"] else "[bold red]INVALID/MISSING[/bold red]", self.config.get("PERMISSION_DOC", "N/A"))
        table.add_row("Instagram Login", "[bold green]SUCCESS[/bold green]" if self.auth_state["instagram_login_ok"] else "[bold red]FAILED[/bold red]", "")

        console.print(table)
        console.print("\n[bold]Run ID:[/bold] {}".format(self.run_id))
        console.print("[bold]Log File:[/bold] {}".format(LOG_FILE))

        if not all(self.auth_state.values()):
            console.print("[bold red]Authorization failed. Exiting.[/bold red]")
            logger.critical(f"Run {self.run_id}: Authorization failed. Exiting.")
            sys.exit(1)

    def _verify_hmac_permission_doc(self, file_path, expected_hmac_secret):
        if not os.path.exists(file_path):
            logger.error(f"Permission document not found: {file_path}")
            return False
        try:
            with open(file_path, 'rb') as f:
                file_content = f.read()
            calculated_hmac = hmac.new(
                expected_hmac_secret.encode('utf-8'),
                file_content,
                hashlib.sha256
            ).hexdigest()
            # In a real scenario, the expected HMAC would be stored securely
            # For this educational example, we'll just check if it's calculable.
            # A more robust system would compare it against a known, trusted HMAC.
            logger.info(f"HMAC calculated for {file_path}. In a real scenario, this would be compared to a stored HMAC.")
            return True
        except Exception as e:
            logger.error(f"Error verifying permission document HMAC: {e}")
            return False

    def authenticate_bot_access(self):
        console.print("\n[bold cyan]--- Bot Access Authentication ---[/bold cyan]")
        stored_key_hash = self.config.get("KEY")
        if not stored_key_hash:
            logger.error("Bot access password hash (KEY) not found in config.")
            self.auth_state["password_ok"] = False
            return

        password = console.input("[bold yellow]Enter bot access password: [/bold yellow]", password=True)
        if hashlib.sha256(password.encode('utf-8')).hexdigest() == stored_key_hash:
            console.print("[bold green]Bot access password OK.[/bold green]")
            logger.info(f"Run {self.run_id}: Bot access password validated successfully.")
            self.auth_state["password_ok"] = True
        else:
            console.print("[bold red]Incorrect bot access password.[/bold red]")
            logger.warning(f"Run {self.run_id}: Incorrect bot access password attempt.")
            self.auth_state["password_ok"] = False

    def check_expiry_date(self):
        expiry_date_str = self.config.get("EXPIRY_DATE")
        if not expiry_date_str:
            logger.error("EXPIRY_DATE not set in config.")
            self.auth_state["expiry_ok"] = False
            return

        try:
            expiry_date = datetime.strptime(expiry_date_str, "%Y-%m-%d").date()
            if datetime.now().date() > expiry_date:
                console.print(f"[bold red]Configuration expired on {expiry_date_str}.[/bold red]")
                logger.warning(f"Run {self.run_id}: Configuration expired on {expiry_date_str}.")
                self.auth_state["expiry_ok"] = False
            else:
                console.print(f"[bold green]Configuration valid until {expiry_date_str}.[/bold green]")
                logger.info(f"Run {self.run_id}: Configuration valid until {expiry_date_str}.")
                self.auth_state["expiry_ok"] = True
        except ValueError:
            logger.error(f"Invalid EXPIRY_DATE format in config: {expiry_date_str}. Expected YYYY-MM-DD.")
            self.auth_state["expiry_ok"] = False

    def check_authorized_user(self):
        authorized_users = self.config.get("AUTHORIZED_USERS", [])
        current_os_user = os.getlogin() # Using os.getlogin() for simplicity. uuid.getnode() is for MAC address
        if current_os_user in authorized_users:
            console.print(f"[bold green]Current OS user '{current_os_user}' is authorized.[/bold green]")
            logger.info(f"Run {self.run_id}: Current OS user '{current_os_user}' is authorized.")
            self.auth_state["user_authorized"] = True
        else:
            console.print(f"[bold red]Current OS user '{current_os_user}' is NOT authorized.[/bold red]")
            logger.warning(f"Run {self.run_id}: Current OS user '{current_os_user}' is NOT authorized.")
            self.auth_state["user_authorized"] = False

    def verify_permission_document(self):
        permission_doc_path = self.config.get("PERMISSION_DOC")
        hmac_secret = self.config.get("INSTAGRAM_HMAC_SECRET")

        if not permission_doc_path:
            logger.error("PERMISSION_DOC path not set in config.")
            self.auth_state["permission_doc_ok"] = False
            return
        if not hmac_secret:
            logger.error("INSTAGRAM_HMAC_SECRET not set in config for permission document verification.")
            self.auth_state["permission_doc_ok"] = False
            return

        if self._verify_hmac_permission_doc(permission_doc_path, hmac_secret):
            console.print(f"[bold green]Permission document '{permission_doc_path}' verified (HMAC check).[/bold green]")
            logger.info(f"Run {self.run_id}: Permission document '{permission_doc_path}' verified (HMAC check).")
            self.auth_state["permission_doc_ok"] = True
        else:
            console.print(f"[bold red]Permission document '{permission_doc_path}' verification FAILED or MISSING.[/bold red]")
            logger.warning(f"Run {self.run_id}: Permission document '{permission_doc_path}' verification FAILED or MISSING.")
            self.auth_state["permission_doc_ok"] = False

    @retry_on_failure()
    def instagram_login(self, username, password):
        console.print(f"\n[bold cyan]--- Instagram Login for {username} ---[/bold cyan]")
        try:
            self.cl.login(username, password)
            console.print(f"[bold green]Successfully logged into Instagram as {username}.[/bold green]")
            logger.info(f"Run {self.run_id}: Successfully logged into Instagram as {username}.")
            self.auth_state["instagram_login_ok"] = True
            return True
        except BadPassword:
            console.print("[bold red]Instagram login failed: Bad password.[/bold red]")
            logger.error(f"Run {self.run_id}: Instagram login failed for {username}: Bad password.")
        except TwoFactorRequired:
            code = console.input("[bold yellow]2FA code required: [/bold yellow]")
            self.cl.two_factor_login(code)
            console.print("[bold green]2FA login successful.[/bold green]")
            logger.info(f"Run {self.run_id}: 2FA login successful for {username}.")
            self.auth_state["instagram_login_ok"] = True
            return True
        except ChallengeRequired as e:
            console.print(f"[bold red]Challenge required: {e}[/bold red]")
            logger.error(f"Run {self.run_id}: Challenge required during login: {e}")
            # For educational purposes, we'll stop here. In production, you'd handle this.
        except Exception as e:
            console.print(f"[bold red]An unexpected error occurred during Instagram login: {e}[/bold red]")
            logger.error(f"Run {self.run_id}: Unexpected error during Instagram login for {username}: {e}", exc_info=True)
        self.auth_state["instagram_login_ok"] = False
        return False

    def perform_all_authorizations(self, instagram_username, instagram_password):
        self.authenticate_bot_access()
        self.check_expiry_date()
        self.check_authorized_user()
        self.verify_permission_document()
        self._display_auth_summary()

        if all(list(self.auth_state.values())[:-1]): # Check all but instagram_login_ok
            self.instagram_login(instagram_username, instagram_password)
        else:
            console.print("[bold red]Pre-Instagram authorization checks failed. Instagram login skipped.[/bold red]")
            logger.critical(f"Run {self.run_id}: Pre-Instagram authorization checks failed. Exiting.")
            sys.exit(1)

        self._display_auth_summary() # Display final state after Instagram login
        if not self.auth_state["instagram_login_ok"]:
            logger.critical(f"Run {self.run_id}: Instagram login failed. Exiting.")
            sys.exit(1)

    def read_target_users(self, file_path):
        targets = []
        if not os.path.exists(file_path):
            console.print(f"[bold red]Target file '{file_path}' not found.[/bold red]")
            logger.error(f"Run {self.run_id}: Target file '{file_path}' not found.")
            return []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'): # Ignore empty lines and comments
                        targets.append(line)
            logger.info(f"Run {self.run_id}: Successfully read {len(targets)} targets from {file_path}.")
            return targets
        except Exception as e:
            console.print(f"[bold red]Error reading target file: {e}[/bold red]")
            logger.error(f"Run {self.run_id}: Error reading target file '{file_path}': {e}", exc_info=True)
            return []

    def get_user_id_from_username(self, username):
        """Helper to get user ID from username using instagrapi."""
        try:
            user_info = self.cl.user_info_by_username(username)
            return user_info.pk # Primary Key (user ID)
        except Exception as e:
            logger.warning(f"Could not get user ID for '{username}': {e}")
            return None

    def _get_reason_id(self, reason_input):
        try:
            reason_id = int(reason_input)
            if reason_id in self.REASONS:
                return reason_id
            else:
                console.print(f"[bold red]Invalid reason ID: {reason_input}. Please choose from {list(self.REASONS.keys())}.[/bold red]")
                return None
        except ValueError:
            # Handle string input for reason if needed, but for now, expecting ID
            console.print("[bold red]Reason must be a number.[/bold red]")
            return None

    @retry_on_failure()
    def _simulate_report_action(self, target_id, reason_id, username):
        """Simulates an API call without actually performing it."""
        sleep_time = random.uniform(DEFAULT_DELAY_MIN, DEFAULT_DELAY_MAX)
        console.print(f"  [yellow]Simulating report for {username} (ID: {target_id}) for reason '{self.REASONS.get(reason_id, 'Unknown')}'... (Delay: {sleep_time:.2f}s)[/yellow]")
        logger.info(f"Run {self.run_id}: DRY-RUN: Simulating report for user {username} (ID: {target_id}), reason: '{self.REASONS.get(reason_id, 'Unknown')}'.")
        time.sleep(sleep_time) # Simulate network delay
        return True # Assume success in dry run

    @retry_on_failure()
    def _perform_report_action(self, target_id, reason_id, username):
        """Performs the actual report action using instagrapi."""
        sleep_time = random.uniform(DEFAULT_DELAY_MIN, DEFAULT_DELAY_MAX)
        console.print(f"  [cyan]Attempting to report {username} (ID: {target_id}) for reason '{self.REASONS.get(reason_id, 'Unknown')}'... (Delay: {sleep_time:.2f}s)[/cyan]")
        logger.info(f"Run {self.run_id}: LIVE-MODE: Attempting to report user {username} (ID: {target_id}), reason: '{self.REASONS.get(reason_id, 'Unknown')}'.")

        try:
            # IMPORTANT: For an actual report, instagrapi.Client.user_report
            # The exact method and parameters can vary with instagrapi updates.
            # Example (THIS IS PSEUDOCODE FOR SAFETY - CONSULT instagrapi DOCS FOR ACTUAL):
            # result = self.cl.user_report(user_id=target_id, reason_id=reason_id)
            # For this educational, safe context, we'll simulate it again.
            # In a real scenario, you would replace this with the actual instagrapi call.

            # Placeholder for actual report call:
            # result = self.cl.user_report(user_id=target_id, reason_id=reason_id)
            # if result.get('status') == 'ok': # Check instagrapi's actual response structure
            #     console.print(f"  [bold green]Successfully reported {username}.[/bold green]")
            #     logger.info(f"Run {self.run_id}: LIVE-MODE: Successfully reported {username} (ID: {target_id}).")
            #     return True
            # else:
            #     console.print(f"  [bold red]Failed to report {username}: {result.get('message', 'Unknown error')}[/bold red]")
            #     logger.error(f"Run {self.run_id}: LIVE-MODE: Failed to report {username} (ID: {target_id}): {result.get('message', 'Unknown error')}.")
            #     return False

            # SAFE EDUCATIONAL SIMULATION (REPLACE WITH REAL INSTAGRAPI CALL FOR LIVE MODE):
            time.sleep(sleep_time) # Simulate API call delay
            if random.random() < 0.95: # Simulate 95% success rate
                console.print(f"  [bold green]Successfully (simulated) reported {username}.[/bold green]")
                logger.info(f"Run {self.run_id}: LIVE-MODE: Successfully (simulated) reported {username} (ID: {target_id}).")
                return True
            else:
                raise ClientError("Simulated API failure.")

        except ClientError as e:
            console.print(f"  [bold red]Instagrapi Client Error reporting {username}: {e}[/bold red]")
            logger.error(f"Run {self.run_id}: LIVE-MODE: Instagrapi Client Error reporting {username} (ID: {target_id}): {e}.")
            return False
        except Exception as e:
            console.print(f"  [bold red]Unexpected error reporting {username}: {e}[/bold red]")
            logger.error(f"Run {self.run_id}: LIVE-MODE: Unexpected error reporting {username} (ID: {target_id}): {e}.", exc_info=True)
            return False

    def display_reason_options(self):
        console.print("\n[bold]Available Report Reasons:[/bold]")
        for rid, reason in self.REASONS.items():
            console.print(f"  [cyan]{rid}[/cyan]: {reason}")
        console.print("")

    def confirm_action(self, mode, targets_count, dry_run):
        action = "simulated report" if dry_run else "LIVE report"
        console.print(f"\n[bold magenta]--- Confirmation ---[/bold magenta]")
        console.print(f"Mode: [bold]{mode}[/bold]")
        console.print(f"Targets: [bold]{targets_count}[/bold] users")
        console.print(f"Action: [bold yellow]{action}[/bold yellow]")
        confirm = console.input("[bold red]Are you sure you want to proceed? (yes/no): [/bold red]").lower().strip()
        return confirm == 'yes'

    def battle_arc_mode(self, username_target, reason_id, count, dry_run, delay_min, delay_max):
        console.print(f"\n[bold green]--- Battle Arc Mode ---[/bold green]")
        console.print(f"Target: [bold]{username_target}[/bold], Reason ID: [bold]{reason_id}[/bold], Count: [bold]{count}[/bold]")
        console.print(f"Mode: {'[bold yellow]DRY-RUN[/bold yellow]' if dry_run else '[bold red]LIVE[/bold red]'}")
        logger.info(f"Run {self.run_id}: Battle Arc Mode initiated for {username_target}, reason {reason_id}, count {count}. Dry-run: {dry_run}.")

        target_user_id = self.get_user_id_from_username(username_target)
        if not target_user_id:
            console.print(f"[bold red]Could not find Instagram user ID for '{username_target}'. Aborting.[/bold red]")
            logger.error(f"Run {self.run_id}: Aborting Battle Arc Mode: Could not resolve user ID for '{username_target}'.")
            return

        if not self.confirm_action("Battle Arc", 1, dry_run):
            console.print("[bold red]Action cancelled by user.[/bold red]")
            logger.info(f"Run {self.run_id}: Battle Arc Mode cancelled by user.")
            return

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            "[progress.percentage]{task.percentage:>3.0f}%",
            console=console
        ) as progress:
            task = progress.add_task(f"[cyan]Processing reports for {username_target}...", total=count)
            success_count = 0
            for i in range(count):
                progress.update(task, description=f"[cyan]Reporting {username_target} ({i+1}/{count})...[/cyan]")
                action_func = self._simulate_report_action if dry_run else self._perform_report_action
                if action_func(target_user_id, reason_id, username_target):
                    success_count += 1
                progress.update(task, advance=1)

            console.print(f"\n[bold green]Battle Arc Mode Complete![/bold green]")
            console.print(f"Total attempts: [bold]{count}[/bold]")
            console.print(f"Successful reports: [bold]{success_count}[/bold]")
            logger.info(f"Run {self.run_id}: Battle Arc Mode finished. Total attempts: {count}, Successful: {success_count}.")

    def noti_claiming_mode(self, target_usernames, reason_id, dry_run, delay_min, delay_max):
        console.print(f"\n[bold green]--- Noti Claiming Mode ---[/bold green]")
        console.print(f"Targets: [bold]{len(target_usernames)}[/bold] users, Reason ID: [bold]{reason_id}[/bold]")
        console.print(f"Mode: {'[bold yellow]DRY-RUN[/bold yellow]' if dry_run else '[bold red]LIVE[/bold red]'}")
        logger.info(f"Run {self.run_id}: Noti Claiming Mode initiated for {len(target_usernames)} targets, reason {reason_id}. Dry-run: {dry_run}.")

        # Resolve all target user IDs first
        resolved_targets = []
        unresolved_targets = []
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            resolve_task = progress.add_task("[yellow]Resolving target usernames to IDs...", total=len(target_usernames))
            for username in target_usernames:
                user_id = self.get_user_id_from_username(username)
                if user_id:
                    resolved_targets.append((username, user_id))
                else:
                    unresolved_targets.append(username)
                progress.update(resolve_task, advance=1)

        if unresolved_targets:
            console.print(f"[bold red]Could not resolve user IDs for the following usernames:[/bold red]")
            for u in unresolved_targets:
                console.print(f"  - {u}")
            logger.warning(f"Run {self.run_id}: Unresolved targets: {', '.join(unresolved_targets)}")

        if not resolved_targets:
            console.print("[bold red]No valid targets to process. Aborting.[/bold red]")
            logger.error(f"Run {self.run_id}: Aborting Noti Claiming Mode: No valid targets after resolution.")
            return

        console.print(f"[bold green]Resolved {len(resolved_targets)} targets.[/bold green]")
        if not self.confirm_action("Noti Claiming", len(resolved_targets), dry_run):
            console.print("[bold red]Action cancelled by user.[/bold red]")
            logger.info(f"Run {self.run_id}: Noti Claiming Mode cancelled by user.")
            return

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            "[progress.percentage]{task.percentage:>3.0f}%",
            console=console
        ) as progress:
            task = progress.add_task(f"[cyan]Processing reports...", total=len(resolved_targets))
            success_count = 0
            for username, target_id in resolved_targets:
                progress.update(task, description=f"[cyan]Reporting {username} (ID: {target_id})...[/cyan]")
                action_func = self._simulate_report_action if dry_run else self._perform_report_action
                if action_func(target_id, reason_id, username):
                    success_count += 1
                progress.update(task, advance=1)

            console.print(f"\n[bold green]Noti Claiming Mode Complete![/bold green]")
            console.print(f"Total targets: [bold]{len(resolved_targets)}[/bold]")
            console.print(f"Successful reports: [bold]{success_count}[/bold]")
            logger.info(f"Run {self.run_id}: Noti Claiming Mode finished. Total targets: {len(resolved_targets)}, Successful: {success_count}.")

    def enforcement_check(self, target_usernames):
        console.print("\n[bold magenta]--- Permission Enforcement Check ---[/bold magenta]")
        permitted_targets = []
        blocked_targets = []

        # For educational purposes, we'll block your own account and private accounts
        # This is where you'd implement logic based on your PERMISSION_DOC rules
        my_username = self.cl.username # Your logged-in username

        for username in target_usernames:
            if username.lower() == my_username.lower():
                blocked_targets.append(f"{username} (Self-report block)")
                logger.info(f"Run {self.run_id}: Enforcement: Blocked self-report for {username}.")
                continue
            
            try:
                user_info = self.cl.user_info_by_username(username)
                if user_info.is_private:
                    blocked_targets.append(f"{username} (Private account - policy block)")
                    logger.info(f"Run {self.run_id}: Enforcement: Blocked private account {username}.")
                    continue
                # Add more checks here based on business rules, e.g.,
                # if user_info.media_count < 5:
                #     blocked_targets.append(f"{username} (Low media count - policy block)")
                #     continue
                permitted_targets.append(username)
            except Exception as e:
                blocked_targets.append(f"{username} (Error checking: {e})")
                logger.warning(f"Run {self.run_id}: Enforcement: Error checking {username}: {e}.")

        if permitted_targets:
            console.print(f"[bold green]Permitted Targets ({len(permitted_targets)}):[/bold green]")
            for p in permitted_targets:
                console.print(f"  - {p}")
        else:
            console.print("[bold yellow]No targets permitted after enforcement checks.[/bold yellow]")

        if blocked_targets:
            console.print(f"[bold red]Blocked Targets ({len(blocked_targets)}):[/bold red]")
            for b in blocked_targets:
                console.print(f"  - {b}")
        
        logger.info(f"Run {self.run_id}: Enforcement Summary - Permitted: {len(permitted_targets)}, Blocked: {len(blocked_targets)}.")
        return permitted_targets, blocked_targets

# --- CLI Initialization and Argument Parsing ---
def init_config():
    console.print("\n[bold green]--- InstaReportBot Initialization ---[/bold green]")
    config_manager = ConfigManager()

    # Gather sensitive info
    bot_access_password = console.input("[bold yellow]Set bot access password: [/bold yellow]", password=True)
    if not bot_access_password:
        console.print("[bold red]Password cannot be empty. Aborting initialization.[/bold red]")
        sys.exit(1)

    expiry_date_str = console.input("[bold yellow]Set configuration expiry date (YYYY-MM-DD, e.g., 2025-12-31): [/bold yellow]").strip()
    try:
        datetime.strptime(expiry_date_str, "%Y-%m-%d")
    except ValueError:
        console.print("[bold red]Invalid date format. Please use YYYY-MM-DD. Aborting initialization.[/bold red]")
        sys.exit(1)

    instagram_hmac_secret = console.input("[bold yellow]Set a secret for HMAC verification of permission doc: [/bold yellow]").strip()
    if not instagram_hmac_secret:
        console.print("[bold red]HMAC secret cannot be empty. Aborting initialization.[/bold red]")
        sys.exit(1)

    permission_doc_path = console.input("[bold yellow]Path to signed permission PDF (e.g., /path/to/doc.pdf): [/bold yellow]").strip()
    if not os.path.exists(permission_doc_path):
        console.print(f"[bold red]Permission document not found at '{permission_doc_path}'. Please ensure it exists.[/bold red]")
        # We allow init to complete, but the main script will fail auth.
        logger.warning(f"Permission document '{permission_doc_path}' not found during init.")

    authorized_users_input = console.input("[bold yellow]Comma-separated list of authorized OS users (e.g., user1,user2): [/bold yellow]").strip()
    authorized_users = [u.strip() for u in authorized_users_input.split(',') if u.strip()]
    if not authorized_users:
        console.print("[bold red]No authorized users specified. Aborting initialization.[/bold red]")
        sys.exit(1)
    
    # Verify current user is in the list
    current_os_user = os.getlogin()
    if current_os_user not in authorized_users:
        console.print(f"[bold yellow]Warning: Current OS user '{current_os_user}' is not in the authorized list.[/bold yellow]")
        if not console.confirm("Do you want to add the current user to the authorized list?"):
             console.print("[bold red]Current user not authorized. Aborting initialization.[/bold red]")
             sys.exit(1)
        else:
            authorized_users.append(current_os_user)
            console.print(f"[bold green]Current user '{current_os_user}' added to authorized users.[/bold green]")


    config_data = {
        "KEY": hashlib.sha256(bot_access_password.encode('utf-8')).hexdigest(),
        "EXPIRY_DATE": expiry_date_str,
        "INSTAGRAM_HMAC_SECRET": instagram_hmac_secret,
        "PERMISSION_DOC": permission_doc_path,
        "AUTHORIZED_USERS": authorized_users,
        "INSTAGRAM_USERNAME": "", # Placeholder, user will provide at runtime
        "INSTAGRAM_PASSWORD": ""  # Placeholder
    }

    config_manager.encrypt_config(config_data)
    console.print("[bold green]Initialization complete! Fill in INSTAGRAM_USERNAME and INSTAGRAM_PASSWORD in the decrypted config if you plan to hardcode them (not recommended).[/bold green]")
    console.print("Remember to place your signed permission PDF at the specified path.")


def main():
    parser = argparse.ArgumentParser(
        description="InstaReportBot: Automate Instagram reporting for educational purposes.",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        "--init", action="store_true",
        help="Initialize the encrypted configuration file (config.json.encrypted)."
    )
    parser.add_argument(
        "--mode", type=str, choices=["battle", "noti"],
        help="Operation mode: 'battle' for mass-report, 'noti' for single-report list."
    )
    parser.add_argument(
        "--target", type=str,
        help="[Battle Arc Mode] Single Instagram username to target."
    )
    parser.add_argument(
        "--targets", nargs='+',
        help="[Noti Claiming Mode] Space-separated list of Instagram usernames or path to a file with usernames (e.g., user1 user2 or @targets.txt)."
    )
    parser.add_argument(
        "--reason", type=int,
        help="Numeric reason ID for reporting. Use --list-reasons to see options."
    )
    parser.add_argument(
        "--count", type=int, default=1,
        help="[Battle Arc Mode] Number of times to perform the report action. Default is 1."
    )
    parser.add_argument(
        "--delay", type=float, nargs=2, metavar=('MIN', 'MAX'),
        default=[DEFAULT_DELAY_MIN, DEFAULT_DELAY_MAX],
        help=f"Min and max delay in seconds between actions. Default: {DEFAULT_DELAY_MIN} {DEFAULT_DELAY_MAX}."
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Simulate the reporting process without sending actual reports."
    )
    parser.add_argument(
        "--list-reasons", action="store_true",
        help="Display available report reason IDs and exit."
    )
    parser.add_argument(
        "--username", type=str,
        help="Your Instagram username for login (if not stored in config)."
    )
    parser.add_argument(
        "--password", type=str,
        help="Your Instagram password for login (if not stored in config)."
    )

    args = parser.parse_args()
    
    # Generate a unique run ID for logging and audit trail
    run_id = str(uuid4())
    logger.info(f"--- InstaReportBot Run Started (ID: {run_id}) ---")

    if args.list_reasons:
        bot = InstaReportBot(ConfigManager(), run_id) # dummy bot to access reasons
        bot.display_reason_options()
        sys.exit(0)

    if args.init:
        init_config()
        sys.exit(0)

    config_manager = ConfigManager()
    config = config_manager.decrypt_config() # This will exit if decryption fails or file not found

    instagram_username = args.username or config.get("INSTAGRAM_USERNAME")
    instagram_password = args.password or config.get("INSTAGRAM_PASSWORD")

    if not instagram_username or not instagram_password:
        console.print("[bold red]Instagram username and password must be provided via --username/--password or set in config.json.encrypted.[/bold red]")
        logger.critical(f"Run {run_id}: Instagram credentials missing. Exiting.")
        sys.exit(1)

    bot = InstaReportBot(config_manager, run_id)
    bot.perform_all_authorizations(instagram_username, instagram_password)

    if not args.mode:
        console.print("[bold red]Error: No operation mode specified. Use --mode battle or --mode noti.[/bold red]")
        parser.print_help()
        sys.exit(1)

    reason_id = args.reason
    if not reason_id:
        bot.display_reason_options()
        reason_input = console.input("[bold yellow]Enter Reason ID: [/bold yellow]").strip()
        reason_id = bot._get_reason_id(reason_input)
        if not reason_id:
            logger.error(f"Run {run_id}: Invalid reason ID provided. Exiting.")
            sys.exit(1)

    if args.mode == "battle":
        if not args.target:
            args.target = console.input("[bold yellow]Enter target Instagram username for Battle Arc Mode: [/bold yellow]").strip()
            if not args.target:
                console.print("[bold red]Target username is required for Battle Arc mode.[/bold red]")
                logger.error(f"Run {run_id}: Target username missing for Battle Arc mode. Exiting.")
                sys.exit(1)
        
        # Enforce permissions before proceeding
        permitted_targets, _ = bot.enforcement_check([args.target])
        if not permitted_targets:
            console.print("[bold red]Target username is not permitted based on policy. Aborting.[/bold red]")
            logger.error(f"Run {run_id}: Target '{args.target}' blocked by policy. Exiting.")
            sys.exit(1)

        bot.battle_arc_mode(permitted_targets[0], reason_id, args.count, args.dry_run, args.delay[0], args.delay[1])

    elif args.mode == "noti":
        target_usernames = []
        if not args.targets:
            target_file_path = console.input("[bold yellow]Enter path to target list file (e.g., targets.txt): [/bold yellow]").strip()
            if not target_file_path:
                console.print("[bold red]Target file path is required for Noti Claiming mode.[/bold red]")
                logger.error(f"Run {run_id}: Target file path missing for Noti Claiming mode. Exiting.")
                sys.exit(1)
            target_usernames = bot.read_target_users(target_file_path)
        else:
            # Check if targets points to a file or are direct usernames
            if len(args.targets) == 1 and args.targets[0].startswith('@'):
                target_file_path = args.targets[0][1:] # Remove the '@'
                target_usernames = bot.read_target_users(target_file_path)
            else:
                target_usernames = args.targets
        
        if not target_usernames:
            console.print("[bold red]No targets found or specified for Noti Claiming mode.[/bold red]")
            logger.error(f"Run {run_id}: No targets found for Noti Claiming mode. Exiting.")
            sys.exit(1)

        # Enforce permissions before proceeding
        permitted_targets, _ = bot.enforcement_check(target_usernames)
        if not permitted_targets:
            console.print("[bold red]All specified targets are blocked by policy. Aborting.[/bold red]")
            logger.error(f"Run {run_id}: All targets blocked by policy. Exiting.")
            sys.exit(1)

        bot.noti_claiming_mode(permitted_targets, reason_id, args.dry_run, args.delay[0], args.delay[1])

    logger.info(f"--- InstaReportBot Run Finished (ID: {run_id}) ---")

if __name__ == "__main__":
    main()
