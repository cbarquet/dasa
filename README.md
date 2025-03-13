# DASA - Async Edition: Optimized for Bug Bounty

## Description 🎯

Dynamic attack surface analyzer (DASA) Async Edition is an offensive security tool **specifically designed for bug bounty hunters**. Its primary focus is the **dynamic and rapid analysis of web application attack surfaces**, enabling you to efficiently identify vulnerabilities eligible for rewards. DASA helps you:

*   **Quickly map the attack surface:** Discover URLs, forms, and entry points in the shortest possible time.
*   **Detect common bug bounty vulnerabilities:** Automatically find potential SQL injections, XSS, command injections, and other web vulnerabilities relevant to bounty programs.
*   **Prioritize targets:** Identify the most interesting areas of a web application for deeper, potentially lucrative research.

With DASA, you can **maximize your time in bug bounties**, focusing on vulnerability analysis instead of wasting time on manual information gathering.

**Script Version:** v0.3.0 -

## Key features for Bug Bounty Hunters 🚀

*   **Lightning-fast asynchronous crawling:** Built with `aiohttp` and `asyncio` to **scan web applications at lightning speed**. Cover a large attack surface in minutes, not hours.
*   **Extended fuzzing focused on bounty-relevant vulnerabilities:** Includes payloads **specifically designed to detect the most common and valuable vulnerabilities in bug bounty programs**: SQL Injection, XSS, Command Injection, and more.
*   **Hidden path detection to find blind spots:** Discover non-publicly linked directories and files using wordlists, **revealing areas of the application that others might overlook**. Find bugs where no one else has looked!
*   **Form analysis for interactive entry points:** Identifies and analyzes HTML forms, **quickly locating user interaction points, which are often rich in vulnerabilities** like XSS and injections.
*   **Detailed and concise reports:** Generates text reports that are **easy to read and present as proof of concept (PoC)** in your bug bounty submissions. 
*   **WAF detection to assess protection level:** Identifies if a WAF is in use, **helping you understand the target's defenses and adapt your attack strategy**.
*   **Precise "Not Found" mode to avoid false positives:** Optimized to **reduce noise and false positives** in hidden path detection, focusing on relevant results.
*   **Customization with wordlists:** **Adapt the wordlists to the specific bug bounty targets you are hunting**. Increase the accuracy of hidden path detection!

## Installation 🛠️

### Prerequisites

Make sure you have **Python 3.8 or higher installed**. Using a virtual environment is recommended to keep your dependencies organized.

### Setup

1.  **Clone the repository (or download the source code):**

    ```bash
    git clone https://github.com/cbarquet/dasa
    cd Dasa
    ```

2.  **Create a virtual environment (optional, but highly recommended for bug bounty!):**

    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Linux/macOS
    venv\Scripts\activate  # On Windows
    ```

3.  **Install the necessary dependencies (quick and easy with pip!):**

    ```bash
    pip install -r requirements.txt
    ```


## Usage - Maximize your bug hunting! 📖

Run the script using this syntax in the command line:

```bash
python3 dasa.py <TARGET_URL> [OPTIONS]
