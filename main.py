#!/usr/bin/env python3

import getpass
import hashlib
import itertools
import math
import os
import re
import secrets
import string
import sys
import time
import urllib.error
import urllib.request

API_URL = "https://api.pwnedpasswords.com/range/"
HEADERS = {
    "User-Agent": "PwnedChecker-1.1 (github.com/fvjy12/password-checker)",

    "Add-Padding": "true",
}

AMBIGUOUS = "l1IO0|`'\""

ATTACK_MODELS = [
    ("онлайн, ограничение (100 попыток/час)", 100 / 3600),
    ("онлайн, без ограничений (10 попыток/сек)", 10),
    ("оффлайн, медленный хэш bcrypt (10 тыс/сек)", 10_000),
    ("оффлайн, SHA-1 на GPU-ферме (100 млрд/сек)", 100_000_000_000),
]

# Точное совпадение в нижнем регистре (или после снятия leet-замены) —
# вердикт «словарный». Список компактный, но покрывает верхушку реальных
# утечек, включая набор на латинице русской раскладки (gfhjkm = «пароль»).
COMMON_PASSWORDS = frozenset("""
    password 123456 123456789 12345678 1234567890 qwerty qwerty123 abc123
    password1 password123 111111 123123 123321 000000 654321 112233 121212
    admin admin123 administrator letmein welcome welcome1 monkey dragon
    football baseball basketball hockey soccer princess sunshine shadow
    master superman batman spiderman trustno1 iloveyou whatever hello
    freedom starwars passw0rd qazwsx qazwsxedc 1q2w3e4r 1qaz2wsx zaq12wsx
    asdfgh asdfghjkl zxcvbn qwe123 asd123 zxc123 123qwe asdasd hunter2
    secret flower summer winter london chocolate cookie pokemon minecraft
    fortnite steam gta5 samsung android iphone google facebook instagram
    vkontakte yandex jordan23 michael jessica ashley loveyou mylove angel
    пароль привет любовь россия москва саша катя настя владимир антон
    йцукен йцукенг фывапролд ячсмит gfhjkm dkflbvbh yfcnz lfif fynjy
""".split())

# Ряды клавиатуры и алфавиты для поиска «пробежек» (qwerty, 1234, йцукен).
SEQUENCE_ALPHABETS = [
    string.ascii_lowercase,
    string.digits,
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "йцукенгшщзхъ", "фывапролджэ", "ячсмитьбю",
]

# Частые подмены: P@ssw0rd → password.
LEET = str.maketrans({
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s",
    "7": "t", "@": "a", "$": "s", "!": "i", "|": "l", "+": "t",
})

# Слоги псевдослов для парольных фраз: слово = 3 слога «согласный+гласный».
CONSONANTS = "бвгджзйклмнпрстфхцчшщ"
VOWELS = "аеёиоуыэюя"


class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"


def enable_colors():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    if os.name == "nt":
        os.system("")


def query_pwned_count(password, retries=2):
    """Вернуть, сколько раз пароль встречался в утечках.

    Схема k-anonymity: считается SHA-1, наружу уходят только первые 5
    шестнадцатеричных символов хэша. Сам пароль и полный хэш не
    отправляются никогда. Кратковременные сбои сети и ответы 5xx
    повторяются с нарастающей паузой.
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    body = None
    last_error = None
    for attempt in range(retries + 1):
        req = urllib.request.Request(API_URL + prefix, headers=HEADERS)
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                body = resp.read().decode("utf-8")
            break
        except urllib.error.HTTPError as e:
            if e.code == 429:
                raise RuntimeError(
                    "HIBP: превышен лимит запросов (429) — подожди минуту и попробуй снова"
                ) from e
            last_error = e
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            last_error = e
        if attempt < retries:
            time.sleep(1.5 * (attempt + 1))

    if body is None:
        raise RuntimeError(f"Нет доступа к API HaveIBeenPwned: {last_error}") from last_error

    for line in body.splitlines():
        line_suffix, _, count = line.partition(":")
        if line_suffix == suffix:
            return int(count)
    return 0

CHAR_CLASSES = [
    (string.ascii_lowercase, 26),
    (string.ascii_uppercase, 26),
    (string.digits, 10),
    (string.punctuation, 32),
]


def alphabet_size(password):
    """Оценка размера алфавита, которым мог пользоваться автор пароля."""
    size = sum(n for chars, n in CHAR_CLASSES if any(c in chars for c in password))
    if any("а" <= c.lower() <= "я" or c.lower() == "ё" for c in password):
        size += 66
    elif any(ord(c) > 127 for c in password):
        size += 100
    return max(size, 1)


def entropy_bits(password):
    return round(len(password) * math.log2(alphabet_size(password)), 1)


def plural(n, one, few, many):
    """Русские формы счёта: 1 бит / 2 бита / 5 бит."""
    n = abs(int(n)) % 100
    if 11 <= n <= 14:
        return many
    n %= 10
    if n == 1:
        return one
    if 2 <= n <= 4:
        return few
    return many


def fmt_bits(bits):
    if abs(bits - round(bits)) > 1e-9:
        return f"{bits} бита"
    return f"{bits} {plural(round(bits), 'бит', 'бита', 'бит')}"


def find_sequences(password):
    """«Пробежки» длины 3+: алфавит (abc), цифры (123), ряды клавиатуры."""
    lower = password.lower()
    runs = []
    for alphabet in SEQUENCE_ALPHABETS:
        for direction in (alphabet, alphabet[::-1]):
            index = {ch: i for i, ch in enumerate(direction)}
            i = 0
            while i < len(lower):
                if lower[i] not in index:
                    i += 1
                    continue
                j = i
                while j + 1 < len(lower) and index.get(lower[j + 1]) == index[lower[j]] + 1:
                    j += 1
                if j - i >= 2:
                    runs.append(lower[i:j + 1])
                i = j + 1 if j > i else i + 1
    return runs


def find_repeats(password):
    """Повторы длины 3+: «aaa», «111»."""
    runs = []
    for _, group in itertools.groupby(password.lower()):
        run = "".join(group)
        if len(run) >= 3:
            runs.append(run)
    return runs


def analyze(password):
    """Наивная энтропия, энтропия с учётом шаблонов и список замечаний.

    Каждая «пробежка» (последовательность или повтор) вычёркивает из
    эффективной длины всё, кроме одного символа: угадав первый символ
    ряда, атакующий угадает весь ряд. Словарные пароли оцениваются как
    малое число догадок независимо от их длины и классов символов.
    """
    issues = []
    eff_len = len(password)

    for run in find_sequences(password):
        eff_len -= len(run) - 1
        shown = run[:10] + ("…" if len(run) > 10 else "")
        issues.append(f"последовательность «{shown}» — такой ряд перебирается первым")
    for run in find_repeats(password):
        eff_len -= len(run) - 1
        shown = run[:10] + ("…" if len(run) > 10 else "")
        issues.append(f"повтор символов «{shown}» — угадал один, угадал все")

    eff_bits = max(eff_len, 1) * math.log2(alphabet_size(password))

    lower = password.lower()
    leet = lower.translate(LEET)
    # Словарная основа: обрезаем все не-буквы в конце (цифры, знаки).
    base = re.sub(r"[^a-zа-яё]+$", "", lower)
    base_leet = re.sub(r"[^a-zа-яё]+$", "", leet)
    if lower in COMMON_PASSWORDS or leet in COMMON_PASSWORDS:
        issues.append("входит в список самых распространённых паролей — есть в каждом словаре подбора")
        eff_bits = min(eff_bits, 15)
    elif base in COMMON_PASSWORDS or base_leet in COMMON_PASSWORDS:
        word = base if base in COMMON_PASSWORDS else base_leet
        issues.append(f"распространённое слово «{word}» с приписками — генераторы подбора пробуют такое первым делом")
        eff_bits = min(max(eff_bits - 15, 10), 25)

    if re.search(r"(?:^|\D)(?:19|20)\d{2}(?:\D|$)", password):
        issues.append("похоже на год (19xx/20xx) — типичная приписка")
        eff_bits = max(eff_bits - 6, 8)

    return entropy_bits(password), round(eff_bits, 1), issues


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
        return f"{C.RED}⛔ НАЙДЕН В УТЕЧКАХ ({pretty} {plural(count, 'раз', 'раза', 'раз')}) — сменить немедленно{C.RESET}"
    if bits < 40:
        return f"{C.RED}⚠ СЛАБЫЙ ({fmt_bits(bits)}) — словарный подбор пройдёт мгновенно{C.RESET}"
    if bits < 60:
        return f"{C.YELLOW}🟡 СРЕДНИЙ ({fmt_bits(bits)}) — допустимо, но можно лучше{C.RESET}"
    return f"{C.GREEN}✅ СТОЙКИЙ ({fmt_bits(bits)}){C.RESET}"


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

    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        if all(any(c in p for c in pwd) for p in pools):
            return pwd


def generate_passphrase(n_words=4, sep="-"):
    """Парольная фраза из произносимых псевдослов.

    Слово = 3 слога «согласный+гласный», часть слов с большой буквы, в
    конце случайная цифра. Пространство вариантов известно точно, поэтому
    словарной атаки «против настоящих слов» нет, а диктовать и запоминать
    такое легче, чем «kX7#mQ2!».
    """
    words = []
    for _ in range(n_words):
        word = "".join(secrets.choice(CONSONANTS) + secrets.choice(VOWELS) for _ in range(3))
        if secrets.randbits(1):
            word = word.capitalize()
        words.append(word)
    return sep.join(words) + secrets.choice(string.digits)


def passphrase_bits(n_words):
    """Энтропия фразы: слоги + случайный регистр слов + финальная цифра."""
    bits = n_words * (3 * math.log2(len(CONSONANTS) * len(VOWELS)) + 1)
    return round(bits + math.log2(10), 1)


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
    try:
        # getpass на Windows читает прямо с консоли (msvcrt), поэтому при
        # перенаправлённом stdin (скрипты, пайпы) зависает — нужен фолбэк.
        if sys.stdin.isatty():
            password = getpass.getpass("Пароль (Enter — отмена): ")
        else:
            password = input("Пароль (Enter — отмена): ")
    except (KeyboardInterrupt, EOFError):
        print()
        return
    if not password:
        return

    try:
        count = query_pwned_count(password)
    except RuntimeError as e:
        print(f"{C.RED}{e}{C.RESET}")
        return

    bits, eff_bits, issues = analyze(password)
    print()
    if count:
        pretty = f"{count:,}".replace(",", " ")
        print(f"  База утечек : {C.RED}найден в {pretty} {plural(count, 'утечке', 'утечках', 'утечках')}{C.RESET}")
    else:
        print(f"  База утечек : {C.GREEN}не найден в известных утечках{C.RESET}")
    print(f"  Длина       : {len(password)} символов, алфавит ~{alphabet_size(password)} символов")
    if eff_bits < bits:
        print(f"  Энтропия    : {fmt_bits(bits)} → {fmt_bits(eff_bits)} с учётом шаблонов")
    else:
        print(f"  Энтропия    : {fmt_bits(bits)}")
    for issue in issues:
        print(f"    {C.YELLOW}!{C.RESET} {issue}")
    print(f"  Полный перебор по моделям атак:")
    for name, t in crack_times(eff_bits):
        print(f"    - {name}: {t}")
    print()
    print(f"  Вердикт: {verdict(count, eff_bits)}")
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

    stats = [(analyze(p)[1], i) for i, p in enumerate(passwords, 1)]

    print(f"Проверяю {len(passwords)} паролей... {C.DIM}(пауза 0.3 сек между запросами){C.RESET}")
    pwned = 0
    for i, pwd in enumerate(passwords, 1):
        try:
            count = query_pwned_count(pwd)
        except RuntimeError as e:
            print(f"{C.RED}{e}{C.RESET}")
            print(f"{C.DIM}Проверено {i - 1} из {len(passwords)} — остальные пропущены.{C.RESET}")
            return
        if count:
            pwned += 1
            pretty = f"{count:,}".replace(",", " ")
            print(f"  #{i} ({len(pwd)} симв.): {C.RED}В УТЕЧКАХ — {pretty} {plural(count, 'раз', 'раза', 'раз')}{C.RESET}")
        else:
            print(f"  #{i} ({len(pwd)} симв.): {C.GREEN}чисто{C.RESET}")
        if i < len(passwords):
            time.sleep(0.3)

    print()
    if pwned:
        print(f"  Итог: {len(passwords) - pwned} чистых, {C.RED}{pwned} в утечках{C.RESET}")
    else:
        print(f"  Итог: все {len(passwords)} чистые 🎉")

    if len(passwords) >= 3:
        print("  Самые слабые (локальная оценка по шаблонам):")
        for eff_bits, i in sorted(stats)[:3]:
            print(f"    - #{i}: {fmt_bits(eff_bits)}")
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
            print(f"  {C.BOLD}{pwd}{C.RESET}  {C.DIM}({fmt_bits(entropy_bits(pwd))}){C.RESET}")
    except ValueError as e:
        print(f"{C.RED}{e}{C.RESET}")
        return
    print()
    print(f"{C.DIM}Сохрани пароль в менеджер паролей — запоминать такой не нужно.{C.RESET}")


def passphrase_flow():
    print(f"\n{C.CYAN}{C.BOLD}=== Генератор парольных фраз ==={C.RESET}")
    print(f"{C.DIM}Произносимые псевдослова: легче запомнить и продиктовать, чем kX7#mQ2!{C.RESET}")
    raw = ask("Сколько слов? (Enter = 4): ", "4")
    try:
        n_words = max(3, min(8, int(raw)))
    except ValueError:
        print(f"{C.YELLOW}Это не число — беру 4{C.RESET}")
        n_words = 4

    print()
    for _ in range(5):
        pwd = generate_passphrase(n_words)
        print(f"  {C.BOLD}{pwd}{C.RESET}  {C.DIM}({fmt_bits(passphrase_bits(n_words))}){C.RESET}")
    print()
    print(f"{C.DIM}Удобно для Wi-Fi, шифрованных архивов и мастер-пароля менеджера.{C.RESET}")


def main():
    enable_colors()
    menu = f"""
{C.BOLD}PWNED CHECKER{C.RESET} — проверка паролей по утечкам HaveIBeenPwned
{C.DIM}k-anonymity: наружу уходят только первые 5 символов SHA-1 хэша{C.RESET}

  1 — Проверить пароль
  2 — Проверить пароли из файла
  3 — Сгенерировать стойкий пароль
  4 — Сгенерировать парольную фразу (легче запомнить)
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
        elif choice == "4":
            passphrase_flow()
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
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nПрервано. Пока! 🔐")
