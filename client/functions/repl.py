from umbral import SecretKey, Signer
from .client import login, upload_file, grant_access, access_file

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
                sk_hex = input("Enter your encryption secret key (hex): ").strip()
                sig_sk_hex = input("Enter your signing secret key (hex): ").strip()

                try:
                    encryption_sk = SecretKey.from_bytes(bytes.fromhex(sk_hex))
                    signing_sk = SecretKey.from_bytes(bytes.fromhex(sig_sk_hex))
                except Exception as e:
                    print("Invalid secret key(s):", e)
                    continue

                signer = Signer(signing_sk)
                grant_access(current_user, receiver, file_name, encryption_sk, signer)

            elif command == "access":
                if not current_user:
                    print("You must login first.")
                    continue
                uploader = input("Uploader username: ").strip()
                file_name = input("File name: ").strip()
                sk_hex = input("Enter your encryption secret key (hex): ").strip()

                try:
                    encryption_sk = SecretKey.from_bytes(bytes.fromhex(sk_hex))
                except Exception as e:
                    print("Invalid secret key:", e)
                    continue

                access_file(file_name, uploader, current_user, encryption_sk)

            else:
                print("Unknown command. Valid commands are: login, upload, grant, access, exit")

        except KeyboardInterrupt:
            print("\nGoodbye!")
            break
        except Exception as e:
            print("Error:", e)
