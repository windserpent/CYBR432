"""
main.py - Encrypted Messaging Application

Menu-driven console application that orchestrates the crypto, message
framing, and connection modules to provide peer-to-peer encrypted
messaging over TCP.

Modules:
    crypto.py        - RSA-OAEP encryption (standalone)
    message_frame.py - Message framing protocol (standalone)
    connection.py    - TCP transport with length-prefixed payloads (standalone)

Author:  Kori Prins
"""

import ipaddress
import os
import platform
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from crypto import (
    RSAEngine,
    RSAKeyPair,
    RSAPublicKey,
    generate_keypair,
    key_fingerprint,
)
from message_frame import (
    MAX_BODY_SIZE,
    Message,
    MessageType,
)
from connection import Connection, DEFAULT_PORT


# ---------------------------------------------------------------------------
# Application class
# ---------------------------------------------------------------------------

class MessagingApp:
    """
    Encrypted messaging application.

    Manages key pairs, sender configuration, a background listener,
    and message send/receive workflows through a menu-driven interface.
    """

    def __init__(self) -> None:
        # OS detection
        self._os_type = platform.system()

        # Path setup -- everything lives in the application root directory
        self._app_dir = Path(__file__).parent.resolve()
        self._public_key_path = self._app_dir / "public_key.pem"
        self._private_key_path = self._app_dir / "private_key.pem"
        self._sender_name_path = self._app_dir / "sender_name.conf"
        self._messages_dir = self._app_dir / "messages"

        # Runtime state
        self._keypair: Optional[RSAKeyPair] = None
        self._engine = RSAEngine()
        self._sender_first_name = ""
        self._sender_last_name = ""
        self._recipient_ip = ""
        self._sequence_number = 0

        # Listener state
        self._listener_thread: Optional[threading.Thread] = None
        self._listener_stop_event = threading.Event()
        self._listener_running = False

    # -----------------------------------------------------------------
    # Startup
    # -----------------------------------------------------------------

    def startup(self) -> None:
        """Initialize the application: paths, keys, and configuration."""
        # Ensure messages directory exists
        self._messages_dir.mkdir(exist_ok=True)

        # Load or generate key pair
        if self._public_key_path.exists() and self._private_key_path.exists():
            self._keypair = RSAKeyPair.load(
                str(self._public_key_path),
                str(self._private_key_path),
            )
            print("Key pair loaded from disk.")
        else:
            print("No key pair found. Generating a 4096-bit RSA key pair ...")
            self._keypair = generate_keypair(4096)
            self._keypair.save(
                str(self._public_key_path),
                str(self._private_key_path),
            )
            print("Key pair generated and saved.")

        # Load sender name if configured
        if self._sender_name_path.exists():
            lines = self._sender_name_path.read_text(encoding="utf-8").splitlines()
            if len(lines) >= 2:
                self._sender_first_name = lines[0].strip()
                self._sender_last_name = lines[1].strip()

    # -----------------------------------------------------------------
    # UI helpers
    # -----------------------------------------------------------------

    def _clear_screen(self) -> None:
        """Clear the terminal screen."""
        if self._os_type == "Windows":
            os.system("cls")
        else:
            os.system("clear")

    def _inbox_count(self) -> int:
        """Count the number of message files in the inbox."""
        return len(list(self._messages_dir.glob("*.bin")))

    def _display_dashboard(self) -> None:
        """Display the status dashboard and main menu."""
        sender_display = "Not Configured"
        if self._sender_first_name or self._sender_last_name:
            sender_display = (
                f"{self._sender_first_name} {self._sender_last_name}".strip()
            )

        recipient_display = self._recipient_ip if self._recipient_ip else ""

        listener_display = "Running" if self._listener_running else "Stopped"

        inbox_count = self._inbox_count()

        print(f"Sender Name: {sender_display}")
        print(f"Recipient IP Address: {recipient_display}")
        print(f"Listener Status: {listener_display}")
        print(f"Messages In Inbox: {inbox_count}")
        print()
        print("Main Menu:")
        print("1. Generate New Key Pair")
        print("2. Configure Sender Name")
        print("3. Set Recipient IP Address")
        print("4. View Mailbox")
        print("5. Start Listener")
        print("6. Stop Listener")
        print("7. Send Message")
        print("8. Quit")
        print()

    # -----------------------------------------------------------------
    # Menu option 1: Generate new key pair
    # -----------------------------------------------------------------

    def _generate_new_keypair(self) -> None:
        """Generate a new key pair, replacing the existing one."""
        print("WARNING: This will replace your existing key pair.")
        print("Any previously received messages will become unreadable.")
        confirm = input("Continue? (y/n): ").strip().lower()
        if confirm != "y":
            print("Cancelled.")
            return

        print("Generating a new 4096-bit RSA key pair ...")
        self._keypair = generate_keypair(4096)
        self._keypair.save(
            str(self._public_key_path),
            str(self._private_key_path),
        )
        print("New key pair generated and saved.")

    # -----------------------------------------------------------------
    # Menu option 2: Configure sender name
    # -----------------------------------------------------------------

    def _configure_sender_name(self) -> None:
        """Prompt the user to set their sender name."""
        print("Configure Sender Name")
        print("(Max 24 characters each)")
        print()

        first = input("First Name: ").strip()
        if len(first.encode("ascii", errors="replace")) > 24:
            print("First name exceeds 24-character limit.")
            return

        last = input("Last Name: ").strip()
        if len(last.encode("ascii", errors="replace")) > 24:
            print("Last name exceeds 24-character limit.")
            return

        self._sender_first_name = first
        self._sender_last_name = last

        self._sender_name_path.write_text(
            f"{first}\n{last}\n", encoding="utf-8",
        )
        print("Sender name saved.")

    # -----------------------------------------------------------------
    # Menu option 3: Set recipient IP address
    # -----------------------------------------------------------------

    def _set_recipient_ip(self) -> None:
        """Prompt the user to set the recipient IP address."""
        addr = input("Enter recipient IPv4 address: ").strip()
        if not self._validate_ipv4(addr):
            print("Invalid IPv4 address.")
            return
        self._recipient_ip = addr
        print(f"Recipient IP set to {self._recipient_ip}")

    @staticmethod
    def _validate_ipv4(addr: str) -> bool:
        """Check whether a string is a valid IPv4 address."""
        try:
            ipaddress.IPv4Address(addr)
            return True
        except ipaddress.AddressValueError:
            return False

    # -----------------------------------------------------------------
    # Menu option 4: View mailbox
    # -----------------------------------------------------------------

    def _view_mailbox(self) -> None:
        """List and display received messages."""
        files = sorted(self._messages_dir.glob("*.bin"))
        if not files:
            print("Mailbox is empty.")
            return

        # Build message listing by decrypting each file
        assert self._keypair is not None
        listing = {}
        for idx, filepath in enumerate(files, start=1):
            sender_display = "(undecryptable)"
            try:
                ciphertext = filepath.read_bytes()
                plaintext = self._engine.decrypt(
                    ciphertext, self._keypair.private,
                )
                msg = Message.unpack(plaintext)
                name = (
                    f"{msg.header.sender_first_name} "
                    f"{msg.header.sender_last_name}"
                ).strip()
                sender_display = name if name else "(no sender name)"
            except Exception:
                pass

            listing[idx] = {
                "filename": filepath.name,
                "filepath": filepath,
                "sender_name": sender_display,
            }

        # Display listing
        print("Inbox:")
        print("-" * 50)
        for idx, info in listing.items():
            print(f"  {idx}. [{info['filename']}] From: {info['sender_name']}")
        print()

        # Prompt to open a message
        selection = input(
            "Enter message number to read (or press Enter to return): "
        ).strip()
        if not selection:
            return

        try:
            sel_idx = int(selection)
        except ValueError:
            print("Invalid selection.")
            return

        if sel_idx not in listing:
            print("Invalid selection.")
            return

        self._open_message(listing[sel_idx]["filepath"])

    def _open_message(self, filepath: Path) -> None:
        """Decrypt and display a single message."""
        ciphertext = filepath.read_bytes()
        assert self._keypair is not None

        try:
            plaintext = self._engine.decrypt(
                ciphertext, self._keypair.private,
            )
            msg = Message.unpack(plaintext)
        except Exception:
            print()
            print("This message cannot be decrypted with the current key pair.")
            print(f"Raw ciphertext ({len(ciphertext)} bytes):")
            print(ciphertext.hex())
            return

        sender_name = (
            f"{msg.header.sender_first_name} "
            f"{msg.header.sender_last_name}"
        ).strip()
        recipient_name = (
            f"{msg.header.recipient_first_name} "
            f"{msg.header.recipient_last_name}"
        ).strip()

        ts = datetime.fromtimestamp(
            msg.header.timestamp, tz=timezone.utc,
        ).strftime("%Y-%m-%d %H:%M:%S UTC")

        print()
        print("-" * 50)
        print(f"From:      {sender_name if sender_name else '(none)'}")
        print(f"To:        {recipient_name if recipient_name else '(none)'}")
        print(f"Timestamp: {ts}")
        print(f"Type:      {msg.header.message_type.name}")
        print(f"Sequence:  {msg.header.sequence_number}")
        print("-" * 50)
        print(msg.body)
        print("-" * 50)

    # -----------------------------------------------------------------
    # Menu option 5: Start listener
    # -----------------------------------------------------------------

    def _start_listener(self) -> None:
        """Start the background listener thread."""
        if self._listener_running:
            print("Listener is already running.")
            return

        self._listener_stop_event.clear()
        self._listener_thread = threading.Thread(
            target=self._listener_loop, daemon=True,
        )
        self._listener_thread.start()
        self._listener_running = True
        print(f"Listener started on port {DEFAULT_PORT}.")

    def _listener_loop(self) -> None:
        """Background loop that accepts connections and saves messages."""
        import socket
        assert self._keypair is not None

        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.settimeout(1.0)
        server_sock.bind(("", DEFAULT_PORT))
        server_sock.listen(1)

        while not self._listener_stop_event.is_set():
            try:
                client_sock, addr = server_sock.accept()
            except socket.timeout:
                continue

            try:
                # Perform handshake manually using length-prefixed protocol
                # Receive peer's public key (client sends first)
                header_raw = self._recv_exact(client_sock, 4)
                length = int.from_bytes(header_raw, "big")
                peer_key_bytes = self._recv_exact(client_sock, length)

                # Send our public key
                our_key_bytes = self._keypair.public.to_pem().encode("utf-8")
                length_header = len(our_key_bytes).to_bytes(4, "big")
                client_sock.sendall(length_header + our_key_bytes)

                # Receive the encrypted message
                msg_header_raw = self._recv_exact(client_sock, 4)
                msg_length = int.from_bytes(msg_header_raw, "big")
                ciphertext = self._recv_exact(client_sock, msg_length)

                # Save to mailbox
                now = datetime.now(tz=timezone.utc)
                epoch_ms = int(now.timestamp() * 1000)
                date_str = now.strftime("%Y%m%d%H%M")
                filename = f"{date_str}_{epoch_ms}.bin"
                filepath = self._messages_dir / filename
                filepath.write_bytes(ciphertext)

            except Exception:
                pass
            finally:
                client_sock.close()

        server_sock.close()

    @staticmethod
    def _recv_exact(sock, num_bytes: int) -> bytes:
        """Read exactly num_bytes from a socket."""
        chunks = []
        remaining = num_bytes
        while remaining > 0:
            chunk = sock.recv(remaining)
            if not chunk:
                raise ConnectionError("Connection closed unexpectedly")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    # -----------------------------------------------------------------
    # Menu option 6: Stop listener
    # -----------------------------------------------------------------

    def _stop_listener(self) -> None:
        """Stop the background listener thread."""
        if not self._listener_running:
            print("Listener is not running.")
            return

        self._listener_stop_event.set()
        if self._listener_thread is not None:
            self._listener_thread.join(timeout=5.0)
        self._listener_running = False
        print("Listener stopped.")

    # -----------------------------------------------------------------
    # Menu option 7: Send message
    # -----------------------------------------------------------------

    def _send_message(self) -> None:
        """Walk the user through composing and sending a message."""
        # Validate recipient IP
        if not self._recipient_ip:
            print(
                "Recipient IP address is not set. "
                "Please set a valid recipient IP address."
            )
            return
        if not self._validate_ipv4(self._recipient_ip):
            print(
                "Recipient IP address is not valid. "
                "Please enter a valid recipient IP address."
            )
            return

        # Check sender name is configured
        if not self._sender_first_name and not self._sender_last_name:
            print("Sender name is not configured. Please configure it first.")
            return

        # Compose message body
        body = ""
        while True:
            if body:
                print(f"Previous message ({len(body)}/{MAX_BODY_SIZE}):")
                print(body)
                print()
                choice = input(
                    "Press Enter to keep, type 'edit' to retype, "
                    "or 'cancel' to abort: "
                ).strip().lower()
                if choice == "cancel":
                    print("Cancelled.")
                    return
                if choice == "":
                    break
                if choice != "edit":
                    print("Invalid choice.")
                    continue

            body = input("Enter message body: ").strip()

            if len(body.encode("ascii", errors="replace")) > MAX_BODY_SIZE:
                print(
                    f"Message body exceeds the maximum message length "
                    f"({len(body)}/{MAX_BODY_SIZE})."
                )
                continue

            if not body:
                print("Message body cannot be empty.")
                continue

            break

        # Optional recipient name
        print()
        recip_first = input(
            "Recipient first name (press Enter to leave blank): "
        ).strip()
        recip_last = input(
            "Recipient last name (press Enter to leave blank): "
        ).strip()

        # Connect, handshake, encrypt, frame, send
        print()
        print(f"Connecting to {self._recipient_ip}:{DEFAULT_PORT} ...")

        assert self._keypair is not None
        conn = Connection()
        try:
            our_key_pem = self._keypair.public.to_pem().encode("utf-8")
            peer_key_bytes = conn.connect_to(
                self._recipient_ip, DEFAULT_PORT, our_key_pem,
            )

            # Deserialize recipient's public key
            peer_key = RSAPublicKey.from_pem(peer_key_bytes.decode("utf-8"))

            # Build the message frame
            sender_id = key_fingerprint(self._keypair.public)
            recipient_id = key_fingerprint(peer_key)

            msg = Message.create(
                body=body,
                message_type=MessageType.TEXT,
                sender_id=sender_id,
                recipient_id=recipient_id,
                sender_first_name=self._sender_first_name,
                sender_last_name=self._sender_last_name,
                recipient_first_name=recip_first,
                recipient_last_name=recip_last,
                sequence_number=self._sequence_number,
            )
            self._sequence_number += 1

            # Pack and encrypt
            packed = msg.pack()
            ciphertext = self._engine.encrypt(packed, peer_key)

            # Send the encrypted message
            conn.send(ciphertext)
            print("Message sent successfully.")

        except Exception as e:
            print(f"Failed to send message: {e}")
        finally:
            conn.close()

    # -----------------------------------------------------------------
    # Menu option 8: Quit
    # -----------------------------------------------------------------

    def _quit(self) -> None:
        """Clean up and exit."""
        if self._listener_running:
            print("Stopping listener ...")
            self._stop_listener()
        print("Goodbye.")

    # -----------------------------------------------------------------
    # Main loop
    # -----------------------------------------------------------------

    def run(self) -> None:
        """Main menu loop."""
        self.startup()

        input("\nPress Enter to continue ...")

        while True:
            self._clear_screen()
            self._display_dashboard()

            choice = input("Select an option: ").strip()

            if choice == "1":
                self._generate_new_keypair()
            elif choice == "2":
                self._configure_sender_name()
            elif choice == "3":
                self._set_recipient_ip()
            elif choice == "4":
                self._view_mailbox()
            elif choice == "5":
                self._start_listener()
            elif choice == "6":
                self._stop_listener()
            elif choice == "7":
                self._send_message()
            elif choice == "8":
                self._quit()
                break
            else:
                print("Invalid selection.")

            input("\nPress Enter to continue ...")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app = MessagingApp()
    app.run()