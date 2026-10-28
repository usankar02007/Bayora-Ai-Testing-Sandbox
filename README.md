# Bayora — Securing AI Safety Testing Infrastructure

## Overview
Bayora is a security-focused platform designed to help protect the infrastructure used for AI safety testing.

## Problem
AI security testing involves adversarial prompts and defensive policies. Without proper access controls and isolation, confidential testing information may be exposed.

## Key Features
- Role-based access control for Red Team, Blue Team, and Admin.
- Confidentiality controls for adversarial prompts and defensive policies.
- Input validation and output filtering.
- Docker-based execution isolation.
- SHA-256 hash-chained audit records for tamper detection.
- Optional web-agent integration with security safeguards.

## Technology Stack
- Frontend: React and TypeScript
- Backend: Python and FastAPI
- Database: PostgreSQL or SQLite, depending on configuration
- Isolation: Docker
- Audit integrity: SHA-256 hash chaining

## Project Status
Bayora is a prototype under development. Features should be considered implemented only when verified through testing.

## Security
Do not commit real API keys, passwords, access tokens, or environment files containing secrets.