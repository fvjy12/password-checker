#!/usr/bin/env python3
# Pwned Checker — проверка паролей по базе утечек HaveIBeenPwned
#
# Пароль никогда не покидает компьютер: наружу уходят только первые
# 5 символов SHA-1 хэша (схема k-anonymity). Зависимостей нет —
# только стандартная библиотека Python.
# v1.0.0

import getpass
import hashlib
import math
import os
import secrets
import string
import time
import urllib.error
import urllib.request

API_URL = "https://api.pwnedpasswords.com/range/"
HEADERS = {
    "User-Agent": "PwnedChecker-1.0 (github.com/fvjy12/password-checker)",
    # сервер дополняет ответ случайными суффиксами — по размеру ответа
    # нельзя понять, найден пароль в базе или нет
    "Add-Padding": "true",
}

AMBIGUOUS = "l1IO0|`'\""

# модели атак: (название, скорость подбора паролей в секунду)
ATTACK_MODELS = [
    ("онлайн, ограничение (100 попыток/час)", 100 / 3600),
    ("онлайн, без ограничений (10 попыток/сек)", 10),
    ("оффлайн, медленный хэш bcrypt (10 тыс/сек)", 10_000),
    ("оффлайн, SHA-1 на GPU-ферме (100 млрд/сек)", 100_000_000_000),
]


# ============================================================
#  Цвета (ANSI)
# ============================================================
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"


def enable_colors():
    if os.name == "nt":
        os.system("")  # включает обработку ANSI-кодов в консоли Windows


# ============================================================
#  HaveIBeenPwned
# ============================================================
def query_pwned_count(password):
    """Вернуть, сколько раз пароль встречался в утечках.

    Схема k-anonymity: считается SHA-1, наружу уходят только первые 5
    шестнадцатеричных символов хэша. Сам пароль и полный хэш не
    отправляются никогда.
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    req = urllib.request.Request(API_URL + prefix, headers=HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read().decode("utf-8")
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise RuntimeError(f"Нет доступа к API HaveIBeenPwned: {e}") from e

    for line in body.splitlines():
        line_suffix, _, count = line.partition(":")
        if line_suffix == suffix:
            return int(count)
    return 0


# ============================================================
#  Энтропия и время подбора
# ============================================================
CHAR_CLASSES = [
    (string.ascii_lowercase, 26),
    (string.ascii_uppercase, 26),
    (string.digits, 10),
    (string.punctuation, 32),
]


def alphabet_size(password):
    """Оценка размера алфавита, которым мог пользоваться автор пароля."""
    size = sum(n for chars, n in CHAR_CLASSES if any(c in chars for c in password))
    if any(ord(c) > 127 for c in password):
        size += 100  # не-ASCII: кириллица, эмодзи и т.д.
    return max(size, 1)


def entropy_bits(password):
    return round(len(password) * math.log2(alphabet_size(password)), 1)


def human_time(seconds):
    if seconds < 1:
        return "мгновенно"
    if seconds < 60:
        return f"{round(seconds)} сек"
    if seconds < 3600:
        return f"{round(seconds / 60)} мин"
    if seconds < 86400:
        return f"{round(seconds / 3600)} ч"
    if seconds < 31_557_600:
        return f"{round(seconds / 86400)} дн"
    years = seconds / 31_557_600
    if years < 1_000:
        return f"{round(years)} лет"
    if years < 1_000_000:
        return f"{round(years / 1e3)} тыс. лет"
    if years < 1_000_000_000:
        return f"{round(years / 1e6)} млн лет"
    if years < 1_000_000_000_000:
        return f"{round(years / 1e9)} млрд лет"
    return "дольше, чем существует Вселенная"


def crack_times(bits):
    """Время полного перебора для каждой модели атаки."""
    rows = []
    for name, rate in ATTACK_MODELS:
        log2_seconds = bits - math.log2(rate)
        if log2_seconds > 90:
            rows.append((name, "практически вечность"))
        else:
            rows.append((name, human_time(2 ** log2_seconds)))
    return rows


def verdict(count, bits):
    if count > 0:
        pretty = f"{count:,}".replace(",", " ")
        return f"{C.RED}⛔ НАЙДЕН В УТЕЧКАХ ({pretty} раз) — сменить немедленно{C.RESET}"
    if bits < 40:
        return f"{C.RED}⚠ СЛАБЫЙ ({bits} бит) — словарный подбор пройдёт мгновенно{C.RESET}"
    if bits < 60:
        return f"{C.YELLOW}🟡 СРЕДНИЙ ({bits} бит) — допустимо, но можно лучше{C.RESET}"
    return f"{C.GREEN}✅ СТОЙКИЙ ({bits} бит){C.RESET}"


# ============================================================
#  Генератор паролей
# ============================================================
def generate_password(length=16, upper=True, digits=True, symbols=True, no_ambiguous=False):
    pools = [string.ascii_lowercase]
    if upper:
        pools.append(string.ascii_uppercase)
    if digits:
        pools.append(string.digits)
    if symbols:
        pools.append(string.punctuation)
    if no_ambiguous:
        pools = ["".join(c for c in p if c not in AMBIGUOUS) for p in pools]
    pools = [p for p in pools if p]
    if not pools:
        raise ValueError("не выбран ни один набор символов")

    alphabet = "".join(pools)
    # secrets.choice — криптографически стойкий источник случайности
    # (не random, который предсказуем)
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        if all(any(c in p for c in pwd) for p in pools):
            return pwd


# ============================================================
#  Интерфейс
# ============================================================
def ask(prompt, default=""):
    line = input(prompt).strip()
    return line if line else default


def ask_yes_no(prompt, default=True):
    line = input(prompt).strip().lower()
    if not line:
        return default
    return line in ("y", "yes", "д", "да", "1")


def check_flow():
    print(f"\n{C.CYAN}{C.BOLD}=== Проверка пароля ==={C.RESET}")
    print(f"{C.DIM}Ввод скрыт. Пароль не сохраняется и не отправляется целиком.{C.RESET}")
    password = getpass.getpass("Пароль (Enter — отмена): ")
    if not password:
        return

    try:
        count = query_pwned_count(password)
    except RuntimeError as e:
        print(f"{C.RED}{e}{C.RESET}")
        return

    bits = entropy_bits(password)
    print()
    if count:
        pretty = f"{count:,}".replace(",", " ")
        print(f"  База утечек : {C.RED}найден в {pretty} утечках{C.RESET}")
    else:
        print(f"  База утечек : {C.GREEN}не найден в известных утечках{C.RESET}")
    print(f"  Длина       : {len(password)} символов, алфавит ~{alphabet_size(password)} символов")
    print(f"  Энтропия    : {bits} бит")
    print(f"  Полный перебор по моделям атак:")
    for name, t in crack_times(bits):
        print(f"    - {name}: {t}")
    print()
    print(f"  Вердикт: {verdict(count, bits)}")
    print(f"{C.DIM}  «Не найден» не значит «безопасен»: пароль всё равно могут украсть{C.RESET}")
    print(f"{C.DIM}   фишингом или кейлоггером. Включай 2FA везде, где можно.{C.RESET}")


def batch_flow():
    print(f"\n{C.CYAN}{C.BOLD}=== Проверка паролей из файла ==={C.RESET}")
    path = ask("Путь к файлу (по одному паролю на строку): ")
    if not path:
        return
    try:
        with open(path.strip('"'), encoding="utf-8", errors="replace") as f:
            passwords = [line.rstrip("\r\n") for line in f]
    except OSError as e:
        print(f"{C.RED}Не удалось открыть файл: {e}{C.RESET}")
        return

    passwords = [p for p in passwords if p and not p.startswith("#")]
    if not passwords:
        print(f"{C.YELLOW}В файле нет паролей{C.RESET}")
        return

    print(f"Проверяю {len(passwords)} паролей... {C.DIM}(пауза 0.3 сек между запросами){C.RESET}")
    pwned = 0
    for i, pwd in enumerate(passwords, 1):
        try:
            count = query_pwned_count(pwd)
        except RuntimeError as e:
            print(f"{C.RED}{e}{C.RESET}")
            return
        if count:
            pwned += 1
            pretty = f"{count:,}".replace(",", " ")
            print(f"  #{i} ({len(pwd)} симв.): {C.RED}В УТЕЧКАХ — {pretty} раз{C.RESET}")
        else:
            print(f"  #{i} ({len(pwd)} симв.): {C.GREEN}чисто{C.RESET}")
        if i < len(passwords):
            time.sleep(0.3)

    print()
    if pwned:
        print(f"  Итог: {len(passwords) - pwned} чистых, {C.RED}{pwned} в утечках{C.RESET}")
    else:
        print(f"  Итог: все {len(passwords)} чистые 🎉")
    print(f"{C.DIM}Хранить пароли в файле — плохая идея, удали его после проверки.{C.RESET}")


def generate_flow():
    print(f"\n{C.CYAN}{C.BOLD}=== Генератор паролей ==={C.RESET}")
    raw = ask("Длина (Enter = 16): ", "16")
    try:
        length = max(8, min(128, int(raw)))
    except ValueError:
        print(f"{C.YELLOW}Это не число — беру 16{C.RESET}")
        length = 16

    upper = ask_yes_no("Заглавные буквы? (Y/n): ", True)
    digits = ask_yes_no("Цифры? (Y/n): ", True)
    symbols = ask_yes_no("Символы !@#$%? (Y/n): ", True)
    no_amb = ask_yes_no("Исключить похожие символы (l, 1, I, O, 0)? (y/N): ", False)

    print()
    try:
        for _ in range(5):
            pwd = generate_password(length, upper, digits, symbols, no_amb)
            print(f"  {C.BOLD}{pwd}{C.RESET}  {C.DIM}({entropy_bits(pwd)} бит){C.RESET}")
    except ValueError as e:
        print(f"{C.RED}{e}{C.RESET}")
        return
    print()
    print(f"{C.DIM}Сохрани пароль в менеджер паролей — запоминать такой не нужно.{C.RESET}")


def main():
    enable_colors()
    menu = f"""
{C.BOLD}PWNED CHECKER{C.RESET} — проверка паролей по утечкам HaveIBeenPwned
{C.DIM}k-anonymity: наружу уходят только первые 5 символов SHA-1 хэша{C.RESET}

  1 — Проверить пароль
  2 — Проверить пароли из файла
  3 — Сгенерировать стойкий пароль
  0 — Выход
"""
    print(menu)
    while True:
        choice = input("Выбор: ").strip().lower()
        if choice == "1":
            check_flow()
        elif choice == "2":
            batch_flow()
        elif choice == "3":
            generate_flow()
        elif choice in ("0", "q", "exit", "выход"):
            print("Пока! 🔐")
            return
        elif choice == "":
            continue
        else:
            print(f"{C.YELLOW}Нет такого пункта{C.RESET}")
            continue
        print(menu)


if __name__ == "__main__":
    main()
