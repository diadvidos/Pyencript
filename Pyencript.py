#!/usr/bin/env python3
"""
Encrypts and decrypts text using a password. Requires no external dependencies.

Scheme: PBKDF2-HMAC-SHA256 to derive the keys, a bitstream
generated with HMAC-SHA256 (CTR mode) for encryption, and HMAC-SHA256 to
authenticate the message (encrypt-then-authenticate).

Format of the encrypted text (in base64, all on one line):
    version (1 byte) | salt (16) | nonce (16) | ciphertext (n) | tag (32)

Usage:
    python encrypt_text.py encrypt
    python encrypt_text.py decrypt
    python encrypt_text.py encrypt --text “hello” --password “key”
    python encrypt_text.py            # interactive menu

Note: To protect truly sensitive data in production, it is advisable to use
the `cryptography` library (AES-GCM or Fernet). This script is standalone and
intended for educational purposes, but it uses standard and properly 

Translated with DeepL.com (free version)
"""

import argparse
import base64
import binascii
import getpass
import hashlib
import hmac
import secrets
import sys

VERSION = b"\x01"
ITERACIONES = 390_000
LONGITUD_SAL = 16
LONGITUD_NONCE = 16
LONGITUD_ETIQUETA = 32
LONGITUD_MINIMA = len(VERSION) + LONGITUD_SAL + LONGITUD_NONCE + LONGITUD_ETIQUETA


class ErrorCifrado(Exception):


def derivar_claves(password: str, sal: bytes) -> tuple[bytes, bytes]:
    material = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), sal, ITERACIONES, dklen=64
    )
    return material[:32], material[32:]


def _flujo(clave: bytes, nonce: bytes, longitud: int) -> bytes:
    salida = bytearray()
    contador = 0
    while len(salida) < longitud:
        bloque = hmac.new(
            clave, nonce + contador.to_bytes(8, "big"), hashlib.sha256
        ).digest()
        salida.extend(bloque)
        contador += 1
    return bytes(salida[:longitud])


def cifrar(texto: str, password: str) -> str:
    if not password:
        raise ErrorCifrado("La contraseña no puede estar vacía.")

    sal = secrets.token_bytes(LONGITUD_SAL)
    nonce = secrets.token_bytes(LONGITUD_NONCE)
    clave_cifrado, clave_mac = derivar_claves(password, sal)

    datos = texto.encode("utf-8")
    cifrado = bytes(a ^ b for a, b in zip(datos, _flujo(clave_cifrado, nonce, len(datos))))

    cuerpo = VERSION + sal + nonce + cifrado
    etiqueta = hmac.new(clave_mac, cuerpo, hashlib.sha256).digest()
    return base64.b64encode(cuerpo + etiqueta).decode("ascii")


def descifrar(texto_cifrado: str, password: str) -> str:
    """Descifra un texto generado por `cifrar` y devuelve el texto original."""
    if not password:
        raise ErrorCifrado("La contraseña no puede estar vacía.")

    limpio = "".join(texto_cifrado.split())
    try:
        crudo = base64.b64decode(limpio, validate=True)
    except (binascii.Error, ValueError):
        raise ErrorCifrado("El texto cifrado no es base64 válido. ¿Lo copiaste completo?") from None

    if len(crudo) < LONGITUD_MINIMA:
        raise ErrorCifrado("El texto cifrado está incompleto o no fue generado por este script.")
    if crudo[:1] != VERSION:
        raise ErrorCifrado("Versión de formato desconocida.")

    inicio = len(VERSION)
    sal = crudo[inicio : inicio + LONGITUD_SAL]
    inicio += LONGITUD_SAL
    nonce = crudo[inicio : inicio + LONGITUD_NONCE]
    inicio += LONGITUD_NONCE
    cifrado = crudo[inicio:-LONGITUD_ETIQUETA]
    etiqueta = crudo[-LONGITUD_ETIQUETA:]

    clave_cifrado, clave_mac = derivar_claves(password, sal)
    esperada = hmac.new(clave_mac, crudo[:-LONGITUD_ETIQUETA], hashlib.sha256).digest()
    if not hmac.compare_digest(etiqueta, esperada):
        raise ErrorCifrado("Contraseña incorrecta o mensaje alterado.")

    datos = bytes(a ^ b for a, b in zip(cifrado, _flujo(clave_cifrado, nonce, len(cifrado))))
    try:
        return datos.decode("utf-8")
    except UnicodeDecodeError:
        raise ErrorCifrado("El contenido descifrado no es texto UTF-8 válido.") from None


def pedir_password(confirmar: bool) -> str:
    if confirmar:
        primera = getpass.getpass("Contraseña: ")
        segunda = getpass.getpass("Repite la contraseña: ")
        if primera != segunda:
            raise ErrorCifrado("Las contraseñas no coinciden.")
        return primera
    return getpass.getpass("Contraseña: ")


def ejecutar(accion: str, texto: str | None, password: str | None) -> None:
    if accion == "cifrar":
        if texto is None:
            print("Escribe el texto a cifrar (Enter para terminar):")
            texto = input("> ")
        if password is None:
            password = pedir_password(confirmar=True)
        resultado = cifrar(texto, password)
        print("\nTexto cifrado (guárdalo completo):\n")
        print(resultado)
    else:
        if texto is None:
            print("Pega el texto cifrado y pulsa Enter:")
            texto = input("> ")
        if password is None:
            password = pedir_password(confirmar=False)
        resultado = descifrar(texto, password)
        print("\nTexto descifrado:\n")
        print(resultado)


def menu_interactivo() -> None:
    while True:
        print("\n=== Cifrado de texto ===")
        print("1) Cifrar texto")
        print("2) Descifrar texto")
        print("3) Salir")
        opcion = input("Elige una opción: ").strip()

        if opcion == "3":
            return
        if opcion in ("1", "2"):
            accion = "cifrar" if opcion == "1" else "descifrar"
            try:
                ejecutar(accion, None, None)
            except ErrorCifrado as error:
                print(f"\nError: {error}")
        else:
            print("Opción no válida.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Cifra y descifra texto con una contraseña.",
    )
    parser.add_argument(
        "accion",
        nargs="?",
        choices=["cifrar", "descifrar"],
        help="cifrar o descifrar (si se omite, se abre un menú interactivo)",
    )
    parser.add_argument("-t", "--texto", help="texto a cifrar o texto cifrado a descifrar")
    parser.add_argument("-p", "--password", help="contraseña (si se omite, se pide de forma oculta)")
    args = parser.parse_args(argv)

    try:
        if args.accion is None:
            menu_interactivo()
        else:
            ejecutar(args.accion, args.texto, args.password)
    except ErrorCifrado as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print("\nCancelado.", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
