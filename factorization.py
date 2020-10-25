#! python3

import math

def primes(n, prime_numbers = []):
    """ Returns  a list of primes <= n """
    if len(prime_numbers) > 0:
        if prime_numbers[-1] >= n:
            return [p for p in prime_numbers if p <= n]
    else:
        return _generate_primes(n + 1, prime_numbers)

def _limit(n):
    return int(math.ceil(math.sqrt(n)))

def _generate_primes(n, prime_numbers = []):
    start = 3

    if len(prime_numbers) > 0:
        sieve = [False] * prime_numbers[-1]

        start = len(sieve)

        while len(sieve) < n:
            sieve.append(True)

        for p in prime_numbers:
            if p < n:
                sieve[p] = True
    else:
        sieve = [True] * n

    for i in range(start, _limit(n), 2):
        if sieve[i]:
            sieve[i * i :: 2 * i] = [False] * int((n - i * i - 1) / (2 * i) + 1)

    return [2] + [i for i in range(3, n, 2) if sieve[i]]

def is_prime(n, prime_numbers = []):
    """ Returns true if n is prime; otherwise false """
    if n < 2:
        return False

    if len(prime_numbers) == 0 or prime_numbers[-1] < n:
        prime_numbers = _generate_primes(n + 1, prime_numbers)

    for p in prime_numbers:
        if n < p:
            return False
        if n == p:
            return True

    return False

def factor(n, prime_numbers = []):
    """ Returns list of prime factors of a integer """
    factors = []

    if not isinstance(n, int):
        return factors

    n = abs(n)

    if n == 0 or n == 1:
        factors.append(n)
    else:
        limit = _limit(n)

        if len(prime_numbers) == 0 or prime_numbers[-1] < limit:
            prime_numbers = _generate_primes(limit + 1, prime_numbers)

        for p in prime_numbers:
            while True:
                if n % p == 0:
                    factors.append(p)

                    n = n // p
                else:
                    break

            if p > n:
                break

        if n != 1:
            factors.append(n)

        if len(factors) == 0:
            factors.append(n)

    return factors
