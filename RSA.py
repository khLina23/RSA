import random
import math
# Функция для вычисления наибольшего общего делителя (НОД) двух чисел
def find_gcd(a, b):
    while b:
        a, b = b, a % b
    return a

# Функция для вычисления обратного элемента по модулю
def find_modular_inverse(a, m):
    """Вычисляет обратный элемент a по модулю m
        a : Число, для которого ищем обратный элемент.
        m : Модуль.
    """
    m0 = m
    x0, x1 = 0, 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        t = m
        m = a % m
        a = t
        t = x0
        x0 = x1 - q * x0
        x1 = t
    if x1 < 0:
        x1 = x1 + m0
    return x1

# проверка простоты числа
def miller_rabin_test(n, k=5):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False
    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    rng = random.SystemRandom() # Random для криптографически надежных случайных чисел
    for _ in range(k):
        a = rng.randrange(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

# генерация простого числа
def generate_prime(length):
    rng = random.SystemRandom()
    while True:
        num = rng.randrange(2**(length-1) + 1, 2**length)
        if miller_rabin_test(num):
            return num

# генерация ключей RSA
def generate_rsa_keys(length=128):
    # 1. Генерация двух простых чисел p и q
    p = generate_prime(length // 2)
    q = generate_prime(length // 2)

    # 2. Вычисление модуля n
    n = p * q

    # 3. Вычисление функции Эйлера phi
    phi = (p - 1) * (q - 1)

    # 4. Выбор открытой экспоненты e
    e = 3 # Выбираем e = 3 для примера
    max_attempts = 1000  # Максимальное количество попыток
    attempts = 0
    while find_gcd(e, phi) != 1:
        if attempts > max_attempts:
            raise Exception("Не удалось найти взаимно простое e с phi")
        e = random.randrange(2, phi)
        if e % 2 == 0:
            e += 1
        attempts += 1

    # 5. Вычисление секретной экспоненты d
    d = find_modular_inverse(e, phi)

    # Возвращаем публичный и приватный ключи
    return (e, n), (d, n)

# Функция для шифрования сообщения
def rsa_encrypt(message, public_key):
    e, n = public_key
    if isinstance(message, int):
        if message >= n:
            raise ValueError(f"Сообщение {message} должно быть меньше чем n = {n}")
        ciphertext = pow(message, e, n)
    elif isinstance(message, str):
        message_int = int.from_bytes(message.encode('utf-8'), 'big')
        if message_int >= n:
            raise ValueError(f"Сообщение слишком длинное, должно быть меньше чем n = {n}")
        ciphertext = pow(message_int, e, n)
    else:
        raise TypeError("Сообщение должно быть числом или строкой")
    return ciphertext

# дешифрование сообщения
def rsa_decrypt(ciphertext, private_key, is_number=False):
    d, n = private_key
    plaintext_int = pow(ciphertext, d, n)
    if is_number:
        return plaintext_int
    try:
      plaintext_bytes = plaintext_int.to_bytes((plaintext_int.bit_length() + 7) // 8, 'big')
      plaintext = plaintext_bytes.decode('utf-8')
      return plaintext
    except UnicodeDecodeError:
       return plaintext_int


def main():
    print("Меню:")
    print("1. Шифрование")
    print("2. Дешифрование")
    print("0. Выход")

    while True:
        choice = input("Введите номер действия: ")

        if choice == '1':
            try:
                message = input("Введите сообщение для шифрования: ")
                print("Генерируем ключи...")
                public_key, private_key = generate_rsa_keys()
                e, n = public_key
                is_number = False
                if message.isdigit():
                     message = int(message)
                     is_number = True

                print("Публичный ключ (e, n):", public_key)
                print("Приватный ключ (d, n):", private_key)
                ciphertext = rsa_encrypt(message, public_key)
                print("Зашифрованное сообщение:", ciphertext)
            except ValueError as e:
                print(f"Ошибка: {e}")
            except TypeError as e:
                print(f"Ошибка: {e}")
            except Exception as e:
                print(f"Произошла ошибка при шифровании: {e}")

        elif choice == '2':
            try:
                d = int(input("Введите d приватного ключа: "))
                n = int(input("Введите n приватного ключа: "))
                private_key = (d, n)
                ciphertext = int(input("Введите зашифрованное сообщение: "))
                decrypted_text = rsa_decrypt(ciphertext, private_key, is_number)
                print("Расшифрованное сообщение:", decrypted_text)
            except Exception as e:
                print(f"Произошла ошибка при дешифровании: {e}")
        elif choice == '0':
            break
        else:
            print("Неверный выбор. Попробуйте снова.")

if __name__ == "__main__":
    main()