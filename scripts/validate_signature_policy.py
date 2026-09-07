#!/usr/bin/env python3
"""Validate the closed Flux controller Kustomization contract."""

import argparse
import os
import stat
import sys
from pathlib import Path

MAX_POLICY_BYTES = 64 * 1024
EXPECTED_FLUX_SYSTEM_KUSTOMIZATION = """apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - controllers
  - access.yaml
"""


def _canonical_text_errors(text, label):
    errors = []
    try:
        encoded = text.encode("utf-8", "strict")
    except UnicodeError:
        return [label + " is not valid UTF-8"]
    if len(encoded) > MAX_POLICY_BYTES:
        errors.append(label + " exceeds the 64 KiB policy ceiling")
    if not text.endswith("\n"):
        errors.append(label + " must end with one LF")
    if "\r" in text:
        errors.append(label + " must use LF line endings")
    if "\t" in text:
        errors.append(label + " must not contain tabs")
    if text.startswith("\ufeff"):
        errors.append(label + " must not contain a UTF-8 BOM")
    if any(ord(character) < 32 and character != "\n" for character in text):
        errors.append(label + " contains a forbidden control character")
    return errors


def flux_system_kustomization_errors(text):
    errors = _canonical_text_errors(text, "Flux system Kustomization")
    if text != EXPECTED_FLUX_SYSTEM_KUSTOMIZATION:
        errors.append("Flux system Kustomization bytes are outside the closed contract")
    return errors


def _read_bounded(path):
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise OSError("policy input is not one regular file")
        data = os.read(descriptor, MAX_POLICY_BYTES + 1)
        if len(data) > MAX_POLICY_BYTES or os.read(descriptor, 1):
            raise OSError("policy input exceeds its bound")
        return data.decode("utf-8", "strict")
    finally:
        os.close(descriptor)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("flux-system-kustomization",))
    parser.add_argument("--file", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        errors = flux_system_kustomization_errors(_read_bounded(args.file))
    except (OSError, UnicodeError):
        errors = ["policy input is unavailable or unsafe"]
    if errors:
        for error in errors:
            print("ERROR " + error, file=sys.stderr)
        return 1
    print("PASS closed Flux controller Kustomization contract")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
