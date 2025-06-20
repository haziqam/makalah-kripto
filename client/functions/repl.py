from umbral import SecretKey, Signer
from .client import login, upload_file, grant_access, access_file
from pathlib import Path

def load_secret_key_from_file(prompt: str) -> SecretKey | None:
    path = input(prompt).strip()
    try:
        key_bytes = Path(path).read_bytes()
        return SecretKey.from_bytes(key_bytes)
    except Exception as e:
        print(f"Failed to load secret key from {path}: {e}")
        return None

def repl():
    current_user = None

    print("Welcome to the Proxy Reencryption Client REPL.")
    print("Commands: login, upload, grant, access, exit")

    while True:
        try:
            command = input(">>> ").strip().lower()

            if command == "exit":
                print("Goodbye!")
                break

            elif command == "login":
                username = input("Username: ").strip()
                password = input("Password: ").strip()

                result = login(username, password)
                if result == False:
                    continue

                current_user = username
                print(f"Logged in as {current_user}")

            elif command == "upload":
                if not current_user:
                    print("You must login first.")
                    continue
                file_path = input("Path to file: ").strip()
                file_name = input("File name to store as: ").strip()
                upload_file(current_user, file_path, file_name)

            elif command == "grant":
                if not current_user:
                    print("You must login first.")
                    continue
                receiver = input("Grant access to (username): ").strip()
                file_name = input("File name: ").strip()

                encryption_sk = load_secret_key_from_file("Path to encryption secret key file: ")
                signing_sk = load_secret_key_from_file("Path to signing secret key file: ")

                if not encryption_sk or not signing_sk:
                    continue

                signer = Signer(signing_sk)
                grant_access(current_user, receiver, file_name, encryption_sk, signer)

            elif command == "access":
                if not current_user:
                    print("You must login first.")
                    continue
                uploader = input("Uploader username: ").strip()
                file_name = input("File name: ").strip()

                encryption_sk = load_secret_key_from_file("Path to your encryption secret key file: ")
                if not encryption_sk:
                    continue

                file_content = access_file(file_name, uploader, current_user, encryption_sk)

                if file_content is None:
                    print("Failed to access or decrypt the file.")
                    continue

                output_path = input("Output path to save the decrypted file: ").strip()

                try:
                    from pathlib import Path
                    Path(output_path).write_text(file_content)
                    print(f"Decrypted file saved to: {output_path}")
                except Exception as e:
                    print(f"Failed to write file: {e}")

            else:
                print("Unknown command. Valid commands are: login, upload, grant, access, exit")

        except KeyboardInterrupt:
            print("\nGoodbye!")
            break
        except Exception as e:
            print("Error:", e)
