# M365 Security Baseline Auditor + Fixer

## Overview
This project aims to simulate securing a real-world Microsoft 365 tenant by building a tool that audits security configurations and identifies gaps based on a defined baseline.

## Goal
- Assess tenant security posture
- Identify misconfigurations
- Provide actionable remediation guidance
- (Future) Automate fixes

---

## Current Features

### 🔐 Secure Tenant Connection
- Connects to Microsoft Graph using tenant-specific authentication
- Supports device-based login (ideal for MSP environments)
- Prevents silent session reuse across tenants
- Displays connected account and tenant details

---

## Why this matters
In multi-tenant MSP environments, authentication sessions can persist and accidentally connect to the wrong tenant.  
This tool enforces explicit tenant selection to ensure accurate and secure auditing.

---

## Status
- Phase 1 – Project setup ✅
- Phase 2 – Secure connection module ✅
- Phase 3 – Identity audit (in progress)