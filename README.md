# 🛡️ Kavach 2.0 — Zero-Leak Privacy & Local Security Guardian

An enterprise-grade, **100% offline-first Chrome/Brave browser extension** built with React, TypeScript, and local client heuristics. Kavach safeguards deeply privacy-conscious users against covert data egress, credential leaks, and tracking surveillance.

---

## 🔒 The Zero-Leak Guarantee
**Your photos, files, typed passwords, and GPS coordinates NEVER leave your computer.**
- **No mandatory cloud dependencies**: All image metadata parsing and visual secret detection runs directly inside browser memory.
- **Optional Local LLM (Ollama)**: Connects to your own machine at `http://localhost:11434` for deep AI vision reasoning.

---

## ✨ Core Defense Modules

### 1. 📤 Pre-Upload Firewall & Local Secret Scanner
* **Guaranteed Interception**: Intercepts file picker (`input[type="file"]`) and Drag-and-Drop events in the browser capture phase **before the host website can read a single byte**.
* **Exact GPS Location Pinpointing**: Binary EXIF parser extracts exact Latitude, Longitude (DMS + Decimal), altitude, device model, and provides a direct Google Maps preview.
* **Local In-Browser Credential Detector**: Scans images locally for plaintext passwords, email addresses, API keys (`sk-...`, `AIza...`), and government IDs (Aadhaar/PAN).
* **🧹 Clean & Upload**: Automatically strips 100% of EXIF/GPS metadata via HTML5 canvas re-encoding before releasing the clean file to the webpage.

### 2. 🔑 Password Destination & Storage Auditor
* **Audits where typed passwords go**: When submitting a login form, Kavach checks the destination:
  - 🛡️ **Enterprise Verified IAM** (Clerk, Supabase Auth, Auth0, Firebase Auth): Confirms credentials are encrypted & hashed via bcrypt/Argon2.
  - ⚠️ **Same-Origin Custom Backend**: Warns that passwords are under the site owner's direct database custody.
  - 🚨 **Unencrypted HTTP / Third-Party Origin**: Triggers an instant critical phishing alarm and warning chime.

### 3. 🌊 Interactive Data Flow & Surveillance Intelligence
* Distinguishes **First-Party Infrastructure** (e.g. YouTube video CDNs keeping data in-house) from **Third-Party Cross-Site Surveillance**.
* **Exact Capability Mapping**:
  - 🖱️ **Session Replay** (Hotjar, Microsoft Clarity, FullStory): Records every mouse movement, scroll depth & keystroke.
  - 🎯 **Cross-Site Ad Profiling** (Meta Pixel, Criteo, Taboola): Builds cross-web purchase graphs.
  - 🖥️ **Hardware Fingerprinting** (FingerprintJS, Canvas): Profiles GPU & audio architecture.
  - 📺 **1st-Party Telemetry** (Google/YouTube): In-house video streaming; data kept in-house.

### 4. 🚨 Malicious Redirect Shield & Popunder Neutralizer
* Detects and neutralizes full-screen transparent clickjacking overlays on torrent and streaming websites.
* Detects rapid multi-hop navigation loops and provides a one-click button: **`🔙 Return to Origin`**.

### 5. 🔔 Audio Chime & Threat Badge
* Generates an offline synthesizer chime using the Web Audio API whenever critical leaks or phishing traps are intercepted.
* Flashes a red dot badge (`!`) on the extension toolbar icon.

---

## 🚀 Quick Setup & Installation

### 1. Load Extension in Chrome / Brave (Ready Out-of-the-Box)
1. Clone or download this repository:
   ```bash
   git clone https://github.com/diiipakkk-08/Kavach.git
   cd Kavach
   ```
2. Build the production bundle:
   ```bash
   npm install
   npm run build
   ```
3. Open your browser:
   - Navigate to `chrome://extensions` or `brave://extensions`.
   - Toggle **Developer mode** (top-right corner).
   - Click **"Load unpacked"**.
   - Select the `dist/` folder inside `Kavach_Main`.
4. **Done!** The extension is now running 100% offline in your browser.

---

## 🦙 Optional: Local AI Setup with Ollama & Gemma

For advanced multimodal AI vision reasoning running **locally on your desktop GPU/CPU** (without sending any images to external cloud APIs):

### Step 1: Install Ollama on Windows
1. Download the Windows installer from [ollama.com/download](https://ollama.com/download) (`OllamaSetup.exe`).
2. Run the installer and complete the setup.
3. Verify installation in Terminal/PowerShell:
   ```powershell
   ollama --version
   ```

### Step 2: Download Local Models
* **For Local Multimodal Vision (Reading text, passwords & IDs in screenshots):**
  ```powershell
  ollama run moondream
  ```
  *(Lightweight vision model, ~1.7 GB. Runs smoothly on laptops).*

  *Or for high-end NVIDIA GPUs (8GB+ VRAM):*
  ```powershell
  ollama run llama3.2-vision:11b
  ```

* **For Text Analysis & Privacy Policies (Gemma 2):**
  ```powershell
  ollama run gemma2:2b
  ```

### Step 3: That's It!
Ollama automatically serves an offline local API at `http://localhost:11434`.
Kavach will automatically detect Ollama if it is running on your machine, or seamlessly fall back to its internal in-browser heuristic scanner if Ollama is not open.

---

## 🧪 Testing the Extension

Open `test-upload.html` in your browser with Kavach installed:
- Click **"📍 Test Sample with Embedded GPS"**: Observe Kavach intercept the file, extract latitude/longitude, and show a Google Maps link.
- Click **"🔑 Test Sensitive Password Screenshot"**: Observe the local scanner immediately catch confidential credentials.
- Click **"🛡️ Run Security Scan"** on any active website to audit client-side risks.

---

## 📄 License
MIT License. Built for hackathons, privacy enthusiasts, and security-first web users.
