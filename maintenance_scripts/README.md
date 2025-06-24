# PhishNet Maintenance Scripts

This folder contains essential scripts for maintaining, testing, and managing your PhishNet deployment. Use these scripts to reset the system, clear data, add sample or manual URLs, and override model predictions.

## Scripts Overview

### 1. `manual_url_management.py`
- **Purpose:** Manually add, update, or delete safe/unsafe URLs. Override model predictions for specific URLs.
- **Usage:**
  ```bash
  python manual_url_management.py
  ```
- **Features:**
  - Add single safe/unsafe URLs
  - Bulk import 100+ safe and 100+ phishing URLs
  - List, update, and delete manual entries
  - View database stats and clear cache
  - Manual entries take priority over model predictions

### 2. `clear_all_data.py`
- **Purpose:** Clear all scan and report data, and Django cache.
- **Usage:**
  ```bash
  python clear_all_data.py
  ```
- **Features:**
  - Deletes all URLScan and Report records
  - Clears Django cache

### 3. `add_sample_data.py`
- **Purpose:** Add a few sample safe and phishing URLs for testing/demo.
- **Usage:**
  ```bash
  python add_sample_data.py
  ```
- **Features:**
  - Adds a few known safe and phishing URLs
  - Creates a demo user if none exists

### 4. `complete_reset.py`
- **Purpose:** Complete system reset and cleanup.
- **Usage:**
  ```bash
  python complete_reset.py
  ```
- **Features:**
  - Clears Django cache
  - Deletes all scan and report data
  - Clears media files
  - Provides restart instructions

---

**Note:**
- Run these scripts from the project root or from within this folder.
- For manual URL management, always use `manual_url_management.py` if you want to override model predictions for specific URLs.
- Use `complete_reset.py` for a full system cleanup.

For more details, see the main project guide or each script's docstring. 