import subprocess
import time
import getpass

from databaser import build_database, reset_database
from auth import init_db, login, verify_credentials
from view import view_logs, filter_by_sport, filter_by_process, mark_processes
from examiner import examine_file
from entity_server import run_test, close_connection


# ----------------------------
# CONFIG / SETUP
# ----------------------------

def build_scan_command():
    input_ignore = input(
        "Enter processes to ignore (comma-separated) ex. steam.exe, GalaxyCommunication.exe, RazerCortex.exe: "
    )

    processes = [p.strip() for p in input_ignore.split(",") if p.strip()]

    extra_processes = []

    for p in processes:
        p_lower = p.lower()

        if p_lower == "steam.exe":
            input_rest = input("Also ignore all steam processes? (y/n): ").strip().lower()
            if input_rest == "y":
                extra_processes.extend([
                    "steamwebhelper.exe",
                    "GameOverlayUI.exe"
                ])

        elif p_lower == "razercortex.exe":
            input_rest = input("Also ignore all razer processes? (y/n): ").strip().lower()
            if input_rest == "y":
                extra_processes.extend([
                    "RazerCentral.exe",
                    "RazerSynapse.exe"
                ])

        elif p_lower == "galaxycommunication.exe":
            input_rest = input("Also ignore all galaxy processes? (y/n): ").strip().lower()
            if input_rest == "y":
                extra_processes.extend([
                    "GalaxyClient.exe",
                    "GalaxyCommunication.exe"
                ])


    with open("ignore_processes.txt", "a") as f:
        for proc in processes:
            f.write(proc + "\n")

    cmd = [".\\scanner.exe"] + processes
    print("Running command:", cmd)

    return cmd

def clean_ignore_list():
    with open("ignore_processes.txt", "w") as f:
        pass  # Clear the file


# ----------------------------
# MENU ACTIONS
# ----------------------------

def handle_logs():
    print("View logs...")

    username, password = login()

    if verify_credentials(username, password):
        print("Access granted. Showing logs...")
        view_logs()
    else:
        print("Access denied. Invalid credentials.")


def handle_advanced_scan(cmd):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    print(f"Starting advanced scan at {timestamp}...")
    print("(login required)...")

    username, password = login()

    if not verify_credentials(username, password):
        print("Access denied. Invalid credentials.")
        return

    print("Access granted. Running advanced scan...")

    state = run_test()

    state["ready"].wait()  # wait until connection exists

    subprocess.run(cmd)

    close_connection(state["conn"], state["server_sock"])

    # Log results
    build_database("connections.log")


def handle_sport_filter():
    input_sport = input("Enter source_port to filter by: ").strip()
    filter_by_sport(input_sport)

def handle_process_filter():
    input_process = input("Enter process name to filter by: ").strip()
    filter_by_process(input_process)


def handle_file_scan():
    file_path = "C:\\Users\\axelg\\Desktop\\ThePortAl\\tuff.exe"
    examine_file(file_path)


# ----------------------------
# MAIN LOOP
# ----------------------------

def main():
    cmd = build_scan_command()

    while True:
        option = input(
            "\nChoose what you want to do:\n"
            "1 - View logs\n"
            "2 - Advanced scan\n"
            "3 - Seek connection (SOURCE_PORT and PROCESS_NAME filter)\n"
            "4 - File metadata scan\n"
            "5 - Exit\n"
            "> "
        ).strip()

        match option:

            case "1":
                    print("Mark processes:")
                    process_windows =(
                    "Windows System",
                    [
                        "System",
                        "Registry",
                        "smss.exe",
                        "csrss.exe",
                        "wininit.exe",
                        "winlogon.exe",
                        "services.exe",
                        "lsass.exe",
                        "svchost.exe",
                        "fontdrvhost.exe",
                        "dwm.exe",
                        "explorer.exe",
                        "taskhostw.exe",
                        "sihost.exe",
                        "RuntimeBroker.exe",
                        "SearchHost.exe",
                        "SearchIndexer.exe",
                        "StartMenuExperienceHost.exe",
                        "ShellExperienceHost.exe",
                        "TextInputHost.exe",
                        "conhost.exe"
                    ]
                    )
                    category, processes = process_windows

                    mark_processes(category, processes)

                    browser_processes =(
                    "Browser",
                    [
                        "chrome.exe",
                        "msedge.exe",
                        "firefox.exe"
                    ]
                )
                    category, processes = browser_processes
                    mark_processes(category, processes)
                    handle_logs()

            case "2":
                handle_advanced_scan(cmd)

            case "3":
                filter_option = input("filter by 1 for source_port or 2 for process name? (1/2): ")
                if filter_option.strip() == "1":
                    handle_sport_filter()
                elif filter_option.strip() == "2":
                    handle_process_filter()

            case "4":
                handle_file_scan()

            case "5":
                print("Exiting...")
                clean_ignore_list()
                with open("connections.log", "w") as f:
                    pass  # Clear the log file
                input_database_clear = input("Also clear the database? (y/n): ").strip().lower()
                if input_database_clear == "y":
                    reset_database()
                print("Goodbye!")
                break

            case _:
                print("Invalid option. Please try again.")


if __name__ == "__main__":
    main()