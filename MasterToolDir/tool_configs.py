"""
OSINT Master Tool — Tool Configuration Definitions
Each tool is defined with its CLI arguments, types, defaults, and category.
The frontend dynamically generates forms from these definitions.
"""

import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SUBTOOLS_DIR = os.path.join(BASE_DIR, "SubTools")

TOOL_CATEGORIES = [
    {
        "id": "username",
        "name": "Username Lookup",
        "icon": "👤",
        "description": "Search for usernames and emails across social networks and platforms."
    },
    {
        "id": "account",
        "name": "Account Enumeration",
        "icon": "📧",
        "description": "Discover accounts linked to emails and phone numbers."
    },
    {
        "id": "network",
        "name": "Network & Domain Recon",
        "icon": "🌐",
        "description": "Reconnaissance on domains, IPs, and network infrastructure."
    },
    {
        "id": "social",
        "name": "Social Media Scraping",
        "icon": "📱",
        "description": "Collect data from social media platforms."
    },
    {
        "id": "data",
        "name": "Data Extraction",
        "icon": "🗂️",
        "description": "Extract metadata and scrape structured data from the web."
    },
    {
        "id": "builtin",
        "name": "Built-in Tools",
        "icon": "⚡",
        "description": "Lightweight OSINT utilities that run directly without external dependencies."
    }
]


TOOLS = {
    # =========================================================================
    # USERNAME LOOKUP
    # =========================================================================
    "sherlock": {
        "id": "sherlock",
        "name": "Sherlock",
        "category": "username",
        "description": "Find usernames across 400+ social networks.",
        "icon": "🔍",
        "executable": "python",
        "script": "-m",
        "module_name": "sherlock_project",
        "cwd": os.path.join(SUBTOOLS_DIR, "Username", "sherlock"),
        "args": [
            {"id": "username", "label": "Username(s)", "type": "text", "required": True,
             "placeholder": "john_doe jane_doe", "help": "One or more usernames to search (space-separated).",
             "is_positional": True},
            {"id": "verbose", "label": "Verbose Output", "type": "toggle", "flag": "--verbose",
             "help": "Display extra debugging information and metrics."},
            {"id": "csv", "label": "Export CSV", "type": "toggle", "flag": "--csv",
             "help": "Create a CSV file with results."},
            {"id": "xlsx", "label": "Export XLSX", "type": "toggle", "flag": "--xlsx",
             "help": "Create an Excel spreadsheet with results."},
            {"id": "txt", "label": "Export TXT", "type": "toggle", "flag": "--txt",
             "help": "Create a text file with results."},
            {"id": "output", "label": "Output File", "type": "text", "flag": "--output",
             "placeholder": "results.txt", "help": "Save output to this file (single username only)."},
            {"id": "folderoutput", "label": "Output Folder", "type": "text", "flag": "--folderoutput",
             "placeholder": "results/", "help": "Save results to this folder (multiple usernames)."},
            {"id": "site_list", "label": "Filter Sites", "type": "text", "flag": "--site",
             "placeholder": "GitHub Twitter Instagram", "help": "Limit to specific sites (space-separated)."},
            {"id": "proxy", "label": "Proxy URL", "type": "text", "flag": "--proxy",
             "placeholder": "socks5://127.0.0.1:1080", "help": "Route requests through a proxy."},
            {"id": "timeout", "label": "Timeout (seconds)", "type": "number", "flag": "--timeout",
             "default": 60, "min": 1, "max": 300, "help": "Seconds to wait per request."},
            {"id": "print_all", "label": "Print All Results", "type": "toggle", "flag": "--print-all",
             "help": "Show sites where username was NOT found too."},
            {"id": "nsfw", "label": "Include NSFW Sites", "type": "toggle", "flag": "--nsfw",
             "help": "Include NSFW sites in the search."},
            {"id": "browse", "label": "Open in Browser", "type": "toggle", "flag": "--browse",
             "help": "Open all found URLs in default browser."},
            {"id": "local", "label": "Use Local Data", "type": "toggle", "flag": "--local",
             "help": "Force use of local data.json instead of fetching remote."},
            {"id": "dump_response", "label": "Dump Responses", "type": "toggle", "flag": "--dump-response",
             "help": "Print raw HTTP responses for debugging."},
            {"id": "json_file", "label": "Custom JSON Data", "type": "text", "flag": "--json",
             "placeholder": "custom_data.json", "help": "Use a custom JSON data file or URL."},
            {"id": "no_color", "label": "Disable Colors", "type": "toggle", "flag": "--no-color",
             "help": "Disable colored terminal output."},
            {"id": "ignore_exclusions", "label": "Ignore Exclusions", "type": "toggle", "flag": "--ignore-exclusions",
             "help": "Ignore upstream site exclusions (may cause false positives)."},
        ]
    },

    "blackbird": {
        "id": "blackbird",
        "name": "Blackbird",
        "category": "username",
        "description": "Search for accounts by username or email across social networks.",
        "icon": "🐦‍⬛",
        "executable": "python",
        "script": os.path.join(SUBTOOLS_DIR, "Username", "blackbird", "blackbird.py"),
        "cwd": os.path.join(SUBTOOLS_DIR, "Username", "blackbird"),
        "args": [
            {"id": "username", "label": "Username(s)", "type": "text", "flag": "--username",
             "placeholder": "john_doe jane_doe", "help": "One or more usernames to search (space-separated)."},
            {"id": "username_file", "label": "Username File", "type": "text", "flag": "--username-file",
             "placeholder": "usernames.txt", "help": "File containing usernames, one per line."},
            {"id": "email", "label": "Email(s)", "type": "text", "flag": "--email",
             "placeholder": "user@example.com", "help": "One or more emails to search (space-separated)."},
            {"id": "email_file", "label": "Email File", "type": "text", "flag": "--email-file",
             "placeholder": "emails.txt", "help": "File containing emails, one per line."},
            {"id": "permute", "label": "Permute Usernames", "type": "toggle", "flag": "--permute",
             "help": "Permute usernames (ignoring single elements)."},
            {"id": "permuteall", "label": "Permute All", "type": "toggle", "flag": "--permuteall",
             "help": "Permute usernames, including all elements."},
            {"id": "csv", "label": "Export CSV", "type": "toggle", "flag": "--csv",
             "help": "Generate a CSV with results."},
            {"id": "pdf", "label": "Export PDF", "type": "toggle", "flag": "--pdf",
             "help": "Generate a PDF with results."},
            {"id": "json", "label": "Export JSON", "type": "toggle", "flag": "--json",
             "help": "Generate a JSON file with results."},
            {"id": "verbose", "label": "Verbose Output", "type": "toggle", "flag": "--verbose",
             "help": "Show verbose output."},
            {"id": "filter", "label": "Site Filter", "type": "text", "flag": "--filter",
             "placeholder": 'cat=social', "help": 'Filter sites by property, e.g. cat=social.'},
            {"id": "no_nsfw", "label": "Exclude NSFW", "type": "toggle", "flag": "--no-nsfw",
             "help": "Remove NSFW sites from the search."},
            {"id": "dump", "label": "Dump HTML", "type": "toggle", "flag": "--dump",
             "help": "Dump HTML content for found accounts."},
            {"id": "proxy", "label": "Proxy URL", "type": "text", "flag": "--proxy",
             "placeholder": "http://127.0.0.1:8080", "help": "Proxy for HTTP requests."},
            {"id": "timeout", "label": "Timeout (seconds)", "type": "number", "flag": "--timeout",
             "default": 30, "min": 1, "max": 300, "help": "Timeout per HTTP request."},
            {"id": "max_concurrent", "label": "Max Concurrent Requests", "type": "number",
             "flag": "--max-concurrent-requests", "default": 30, "min": 1, "max": 100,
             "help": "Maximum number of concurrent requests."},
            {"id": "no_update", "label": "Skip Updates", "type": "toggle", "flag": "--no-update",
             "help": "Don't update site lists."},
            {"id": "ai", "label": "Use AI Features", "type": "toggle", "flag": "--ai",
             "help": "Enable AI analysis of results."},
        ]
    },

    "holehe_username": {
        "id": "holehe_username",
        "name": "Holehe",
        "category": "username",
        "description": "Check if an email is attached to accounts on 120+ sites.",
        "icon": "📨",
        "executable": "python",
        "script": os.path.join(SUBTOOLS_DIR, "Username", "holehe", "holehe", "core.py"),
        "cwd": os.path.join(SUBTOOLS_DIR, "Username", "holehe"),
        "use_module": "holehe",
        "args": [
            {"id": "email", "label": "Target Email", "type": "text", "required": True,
             "placeholder": "target@example.com", "help": "Email address to look up.",
             "is_positional": True},
            {"id": "onlyused", "label": "Only Show Used", "type": "toggle", "flag": "--only-used",
             "help": "Only display sites where the email is registered."},
            {"id": "nopasswordrecovery", "label": "No Password Recovery", "type": "toggle",
             "flag": "--no-password-recovery", "help": "Don't trigger password recovery flows."},
            {"id": "csvoutput", "label": "Export CSV", "type": "toggle", "flag": "--csv",
             "help": "Create a CSV with results."},
            {"id": "timeout", "label": "Timeout (seconds)", "type": "number", "flag": "--timeout",
             "default": 10, "min": 1, "max": 120, "help": "Max timeout per request."},
            {"id": "nocolor", "label": "No Color", "type": "toggle", "flag": "--no-color",
             "help": "Disable colored output."},
            {"id": "noclear", "label": "No Clear Screen", "type": "toggle", "flag": "--no-clear",
             "help": "Don't clear terminal before showing results."},
        ]
    },

    # =========================================================================
    # ACCOUNT ENUMERATION
    # =========================================================================
    "holehe_account": {
        "id": "holehe_account",
        "name": "Holehe",
        "category": "account",
        "description": "Discover which platforms an email is registered on.",
        "icon": "📨",
        "executable": "python",
        "script": os.path.join(SUBTOOLS_DIR, "AccountEnumeration", "holehe", "holehe", "core.py"),
        "cwd": os.path.join(SUBTOOLS_DIR, "AccountEnumeration", "holehe"),
        "use_module": "holehe",
        "args": [
            {"id": "email", "label": "Target Email", "type": "text", "required": True,
             "placeholder": "target@example.com", "help": "Email address to check.",
             "is_positional": True},
            {"id": "onlyused", "label": "Only Show Used", "type": "toggle", "flag": "--only-used",
             "help": "Only display sites where the email is registered."},
            {"id": "nopasswordrecovery", "label": "No Password Recovery", "type": "toggle",
             "flag": "--no-password-recovery", "help": "Don't trigger password recovery."},
            {"id": "csvoutput", "label": "Export CSV", "type": "toggle", "flag": "--csv",
             "help": "Export results to CSV."},
            {"id": "timeout", "label": "Timeout (seconds)", "type": "number", "flag": "--timeout",
             "default": 10, "min": 1, "max": 120, "help": "Max timeout per request."},
            {"id": "nocolor", "label": "No Color", "type": "toggle", "flag": "--no-color",
             "help": "Disable colored output."},
            {"id": "noclear", "label": "No Clear Screen", "type": "toggle", "flag": "--no-clear",
             "help": "Don't clear terminal."},
        ]
    },

    "ignorant": {
        "id": "ignorant",
        "name": "Ignorant",
        "category": "account",
        "description": "Check if a phone number is linked to accounts on various sites.",
        "icon": "📱",
        "executable": "python",
        "script": os.path.join(SUBTOOLS_DIR, "AccountEnumeration", "ignorant", "ignorant", "core.py"),
        "cwd": os.path.join(SUBTOOLS_DIR, "AccountEnumeration", "ignorant"),
        "use_module": "ignorant",
        "args": [
            {"id": "country_code", "label": "Country Code", "type": "text", "required": True,
             "placeholder": "1", "help": "Country code without + (e.g. 1 for US, 44 for UK).",
             "is_positional": True, "position": 0},
            {"id": "phone", "label": "Phone Number", "type": "text", "required": True,
             "placeholder": "5551234567", "help": "Phone number without country code.",
             "is_positional": True, "position": 1},
            {"id": "onlyused", "label": "Only Show Used", "type": "toggle", "flag": "--only-used",
             "help": "Only display sites where the phone is registered."},
            {"id": "timeout", "label": "Timeout (seconds)", "type": "number", "flag": "--timeout",
             "default": 10, "min": 1, "max": 120, "help": "Max timeout per request."},
            {"id": "nocolor", "label": "No Color", "type": "toggle", "flag": "--no-color",
             "help": "Disable colored output."},
            {"id": "noclear", "label": "No Clear Screen", "type": "toggle", "flag": "--no-clear",
             "help": "Don't clear terminal."},
        ]
    },

    # =========================================================================
    # NETWORK & DOMAIN RECON
    # =========================================================================
    "theharvester": {
        "id": "theharvester",
        "name": "theHarvester",
        "category": "network",
        "description": "Gather emails, subdomains, hosts, employee names, open ports and banners from public sources.",
        "icon": "🌾",
        "executable": "python",
        "script": "-m",
        "module_name": "theHarvester",
        "cwd": os.path.join(SUBTOOLS_DIR, "NetworkDomainRecon", "theHarvester"),
        "args": [
            {"id": "domain", "label": "Target Domain", "type": "text", "required": True,
             "flag": "-d", "placeholder": "example.com", "help": "Domain to search."},
            {"id": "source", "label": "Data Source", "type": "select", "flag": "-b",
             "options": ["all", "baidu", "bing", "bingapi", "certspotter", "crtsh", "dnsdumpster",
                         "dogpile", "duckduckgo", "exalead", "google", "googleCSE",
                         "hunter", "intelx", "linkedin", "netcraft", "otx", "securityTrails",
                         "shodan", "threatcrowd", "trello", "twitter", "virustotal", "yahoo"],
             "default": "all", "help": "Data source to use for searching."},
            {"id": "limit", "label": "Result Limit", "type": "number", "flag": "-l",
             "default": 500, "min": 1, "max": 10000, "help": "Limit the number of search results."},
            {"id": "start", "label": "Start Result", "type": "number", "flag": "-S",
             "default": 0, "min": 0, "help": "Start with result number X."},
            {"id": "dns_brute", "label": "DNS Brute Force", "type": "toggle", "flag": "-c",
             "help": "Perform DNS brute force on the domain."},
            {"id": "dns_lookup", "label": "DNS Lookup", "type": "toggle", "flag": "-n",
             "help": "Enable DNS lookup."},
            {"id": "dns_server", "label": "DNS Server", "type": "text", "flag": "-e",
             "placeholder": "8.8.8.8", "help": "Custom DNS server for lookup."},
            {"id": "virtual_host", "label": "Virtual Host Verification", "type": "toggle", "flag": "-v",
             "help": "Verify hostname via DNS resolution."},
            {"id": "takeover", "label": "Takeover Check", "type": "toggle", "flag": "-t",
             "help": "Check for subdomain takeovers."},
            {"id": "screenshots", "label": "Take Screenshots", "type": "toggle", "flag": "-s",
             "help": "Take screenshots of discovered hosts."},
            {"id": "filename", "label": "Output File", "type": "text", "flag": "-f",
             "placeholder": "results.html", "help": "Save results to HTML/XML file."},
        ]
    },

    "shodan": {
        "id": "shodan",
        "name": "Shodan",
        "category": "network",
        "description": "Search engine for Internet-connected devices. Query open ports, services, and vulnerabilities.",
        "icon": "🛰️",
        "executable": "python",
        "script": "-m",
        "module_name": "shodan",
        "cwd": os.path.join(SUBTOOLS_DIR, "NetworkDomainRecon", "shodan"),
        "requires_api_key": "shodan_api_key",
        "args": [
            {"id": "command", "label": "Command", "type": "select", "required": True,
             "options": ["search", "host", "info", "count", "scan", "stats", "domain"],
             "default": "search", "help": "Shodan command to execute."},
            {"id": "query", "label": "Query / Target", "type": "text", "required": True,
             "placeholder": "apache port:8080", "help": "Search query or target IP/domain.",
             "is_positional": True},
            {"id": "facets", "label": "Facets", "type": "text", "flag": "--facets",
             "placeholder": "country,org", "help": "List of properties to get summary of."},
            {"id": "limit", "label": "Result Limit", "type": "number", "flag": "--limit",
             "default": 100, "min": 1, "max": 1000, "help": "Number of results to return."},
            {"id": "fields", "label": "Fields", "type": "text", "flag": "--fields",
             "placeholder": "ip_str,port,org", "help": "Comma-separated list of fields to display."},
            {"id": "separator", "label": "Separator", "type": "text", "flag": "--separator",
             "placeholder": "\\t", "help": "Field separator for output."},
            {"id": "no_color", "label": "No Color", "type": "toggle", "flag": "--no-color",
             "help": "Disable colored output."},
        ]
    },

    "spiderfoot": {
        "id": "spiderfoot",
        "name": "SpiderFoot",
        "category": "network",
        "description": "Automated OSINT collection for IPs, domains, emails, names, and more via 200+ modules.",
        "icon": "🕷️",
        "executable": "python",
        "script": os.path.join(SUBTOOLS_DIR, "NetworkDomainRecon", "spiderfoot", "sf.py"),
        "cwd": os.path.join(SUBTOOLS_DIR, "NetworkDomainRecon", "spiderfoot"),
        "args": [
            {"id": "listen", "label": "Web UI (IP:Port)", "type": "text", "flag": "-l",
             "placeholder": "127.0.0.1:5001", "help": "Start SpiderFoot web UI on this address."},
            {"id": "target", "label": "Scan Target", "type": "text", "flag": "-s",
             "placeholder": "example.com", "help": "Target for the scan (domain, IP, email, etc)."},
            {"id": "modules", "label": "Modules", "type": "text", "flag": "-m",
             "placeholder": "sfp_dns,sfp_whois", "help": "Comma-separated list of modules to enable."},
            {"id": "usecase", "label": "Use Case", "type": "select", "flag": "-u",
             "options": ["", "all", "footprint", "investigate", "passive"],
             "help": "Auto-select modules by use case."},
            {"id": "types", "label": "Event Types", "type": "text", "flag": "-t",
             "placeholder": "IP_ADDRESS,EMAILADDR", "help": "Comma-separated event types to collect."},
            {"id": "output", "label": "Output Format", "type": "select", "flag": "-o",
             "options": ["", "tab", "csv", "json"], "help": "Output format."},
            {"id": "max_threads", "label": "Max Threads", "type": "number", "flag": "-max-threads",
             "default": 3, "min": 1, "max": 50, "help": "Max concurrent modules."},
            {"id": "debug", "label": "Debug Mode", "type": "toggle", "flag": "-d",
             "help": "Enable debug output."},
            {"id": "strict", "label": "Strict Mode", "type": "toggle", "flag": "-x",
             "help": "Only enable modules that directly consume the target type."},
            {"id": "quiet", "label": "Quiet Mode", "type": "toggle", "flag": "-q",
             "help": "Disable logging."},
            {"id": "filter", "label": "Filter Output", "type": "toggle", "flag": "-f",
             "help": "Filter out unrequested event types."},
            {"id": "no_header", "label": "No Headers", "type": "toggle", "flag": "-H",
             "help": "Don't print field headers."},
            {"id": "strip_newlines", "label": "Strip Newlines", "type": "toggle", "flag": "-n",
             "help": "Remove newlines from data."},
            {"id": "show_source", "label": "Show Source", "type": "toggle", "flag": "-r",
             "help": "Include source data field in output."},
            {"id": "list_modules", "label": "List Modules", "type": "toggle", "flag": "-M",
             "help": "Show available modules and exit."},
            {"id": "list_types", "label": "List Event Types", "type": "toggle", "flag": "-T",
             "help": "Show available event types and exit."},
        ]
    },

    "recon_ng": {
        "id": "recon_ng",
        "name": "Recon-ng",
        "category": "network",
        "description": "Full-featured web reconnaissance framework with modular plugins.",
        "icon": "🔬",
        "executable": "python",
        "script": os.path.join(SUBTOOLS_DIR, "NetworkDomainRecon", "recon-ng", "recon-ng", "recon-ng"),
        "cwd": os.path.join(SUBTOOLS_DIR, "NetworkDomainRecon", "recon-ng"),
        "args": [
            {"id": "workspace", "label": "Workspace", "type": "text", "flag": "-w",
             "placeholder": "myworkspace", "help": "Workspace name."},
            {"id": "module", "label": "Module", "type": "text", "flag": "-m",
             "placeholder": "recon/domains-hosts/google_site_web",
             "help": "Module to load."},
            {"id": "command", "label": "Command", "type": "text", "flag": "-C",
             "placeholder": "help", "help": "Command to execute in the framework."},
            {"id": "version", "label": "Show Version", "type": "toggle", "flag": "--version",
             "help": "Show version and exit."},
        ]
    },

    # =========================================================================
    # SOCIAL MEDIA SCRAPING
    # =========================================================================
    "snscrape": {
        "id": "snscrape",
        "name": "SNScrape",
        "category": "social",
        "description": "Scrape social media posts, users, and profiles from Twitter, Reddit, and more.",
        "icon": "📊",
        "executable": "python",
        "script": "-m",
        "module_name": "snscrape._cli",
        "cwd": os.path.join(SUBTOOLS_DIR, "SocialMediaScraping", "snscrape"),
        "args": [
            {"id": "platform", "label": "Platform", "type": "select", "required": True,
             "options": ["twitter-search", "twitter-user", "twitter-hashtag",
                         "reddit-search", "reddit-subreddit", "reddit-user",
                         "instagram-user", "instagram-hashtag",
                         "facebook-user", "facebook-group",
                         "vkontakte-user", "telegram-channel"],
             "default": "twitter-search", "help": "Social media platform and mode.",
             "is_positional": True, "position": 0},
            {"id": "query", "label": "Query / Username", "type": "text", "required": True,
             "placeholder": "search query or @username", "help": "Search query or target username.",
             "is_positional": True, "position": 1},
            {"id": "max_results", "label": "Max Results", "type": "number", "flag": "--max-results",
             "default": 100, "min": 1, "max": 10000, "help": "Maximum number of results."},
            {"id": "jsonl", "label": "JSONL Output", "type": "toggle", "flag": "--jsonl",
             "help": "Output as JSON Lines."},
            {"id": "with_entity", "label": "With Entity", "type": "toggle", "flag": "--with-entity",
             "help": "Include the entity (user/channel) in the output."},
            {"id": "since", "label": "Since Date", "type": "text", "flag": "--since",
             "placeholder": "2024-01-01", "help": "Only return content since this date."},
        ]
    },

    "osintgram": {
        "id": "osintgram",
        "name": "Osintgram",
        "category": "social",
        "description": "Interactive Instagram OSINT tool — retrieve followers, photos, stories, and more.",
        "icon": "📸",
        "executable": "python",
        "script": os.path.join(SUBTOOLS_DIR, "SocialMediaScraping", "Osintgram", "main.py"),
        "cwd": os.path.join(SUBTOOLS_DIR, "SocialMediaScraping", "Osintgram"),
        "args": [
            {"id": "target", "label": "Target Username", "type": "text", "required": True,
             "placeholder": "instagram_user", "help": "Instagram username to analyze.",
             "is_positional": True},
            {"id": "command", "label": "Command", "type": "select", "flag": "-c",
             "options": ["info", "addrs", "captions", "commentdata", "comments",
                         "followers", "followings", "fwersemail", "fwingsemail",
                         "fwersnumber", "fwingsnumber", "hashtags", "likes",
                         "mediatype", "photodes", "photos", "propic", "stories",
                         "tagged", "wcommented", "wtagged"],
             "default": "info", "help": "Command to run on the target."},
            {"id": "json", "label": "Export JSON", "type": "toggle", "flag": "-j",
             "help": "Save output as JSON file."},
            {"id": "file", "label": "Save to File", "type": "toggle", "flag": "-f",
             "help": "Save output to text file."},
            {"id": "output", "label": "Output Directory", "type": "text", "flag": "-o",
             "placeholder": "output/", "help": "Directory to store downloaded content."},
            {"id": "cookies", "label": "Clear Cookies", "type": "toggle", "flag": "-C",
             "help": "Clear previous session cookies."},
        ]
    },

    "instalooter": {
        "id": "instalooter",
        "name": "InstaLooter",
        "category": "social",
        "description": "Download photos and videos from Instagram profiles and hashtags.",
        "icon": "🖼️",
        "executable": "python",
        "script": "-m",
        "module_name": "instalooter",
        "cwd": os.path.join(SUBTOOLS_DIR, "SocialMediaScraping", "InstaLooter"),
        "args": [
            {"id": "mode", "label": "Mode", "type": "select", "required": True,
             "options": ["user", "hashtag", "post"],
             "default": "user", "help": "Download mode.",
             "is_positional": True, "position": 0},
            {"id": "target", "label": "Target", "type": "text", "required": True,
             "placeholder": "username or #hashtag", "help": "Instagram username or hashtag.",
             "is_positional": True, "position": 1},
            {"id": "directory", "label": "Output Directory", "type": "text", "required": True,
             "placeholder": "downloads/", "help": "Where to save downloaded content.",
             "is_positional": True, "position": 2},
            {"id": "num_posts", "label": "Number of Posts", "type": "number", "flag": "-n",
             "default": 50, "min": 1, "max": 10000, "help": "Number of posts to download."},
            {"id": "videos", "label": "Include Videos", "type": "toggle", "flag": "-v",
             "help": "Download videos in addition to photos."},
            {"id": "jobs", "label": "Parallel Jobs", "type": "number", "flag": "-j",
             "default": 16, "min": 1, "max": 64, "help": "Number of parallel download jobs."},
            {"id": "template", "label": "Filename Template", "type": "text", "flag": "-T",
             "placeholder": "{id}", "help": "Template for output filenames."},
            {"id": "dump_json", "label": "Dump JSON", "type": "toggle", "flag": "-d",
             "help": "Dump metadata as JSON alongside downloads."},
        ]
    },

    "telepathy": {
        "id": "telepathy",
        "name": "Telepathy",
        "category": "social",
        "description": "Telegram OSINT toolkit — analyze channels, groups, members, and messages.",
        "icon": "✈️",
        "executable": "python",
        "script": "-m",
        "module_name": "src.telepathy.telepathy",
        "cwd": os.path.join(SUBTOOLS_DIR, "SocialMediaScraping", "Telepathy"),
        "args": [
            {"id": "target", "label": "Target Channel/Group", "type": "text", "required": True,
             "flag": "-t", "placeholder": "channel_name", "help": "Telegram channel or group."},
            {"id": "comprehensive", "label": "Comprehensive Scan", "type": "toggle", "flag": "-c",
             "help": "Run a comprehensive scan."},
            {"id": "forwards_check", "label": "Forwards Check", "type": "toggle", "flag": "-f",
             "help": "Check forwarded messages."},
            {"id": "media", "label": "Download Media", "type": "toggle", "flag": "-m",
             "help": "Download media from the target."},
            {"id": "user_check", "label": "User Check", "type": "toggle", "flag": "-u",
             "help": "Check user information."},
            {"id": "location", "label": "Location Check", "type": "toggle", "flag": "-l",
             "help": "Check for location data."},
            {"id": "export", "label": "Export Data", "type": "toggle", "flag": "-e",
             "help": "Export collected data."},
        ]
    },

    # =========================================================================
    # DATA EXTRACTION
    # =========================================================================
    "exiftool": {
        "id": "exiftool",
        "name": "ExifTool",
        "category": "data",
        "description": "Extract EXIF metadata from images, documents, and other files.",
        "icon": "🏷️",
        "executable": "exiftool",
        "script": None,
        "cwd": os.path.join(SUBTOOLS_DIR, "DataExtraction", "pyexiftool"),
        "args": [
            {"id": "file", "label": "File/Folder Path", "type": "text", "required": True,
             "placeholder": "C:\\path\\to\\image.jpg", "help": "File or folder to extract metadata from.",
             "is_positional": True},
            {"id": "recursive", "label": "Recursive", "type": "toggle", "flag": "-r",
             "help": "Process folders recursively."},
            {"id": "json_output", "label": "JSON Output", "type": "toggle", "flag": "-json",
             "help": "Output in JSON format."},
            {"id": "csv_output", "label": "CSV Output", "type": "toggle", "flag": "-csv",
             "help": "Output in CSV format."},
            {"id": "gps_only", "label": "GPS Data Only", "type": "toggle", "flag": "-gps:all",
             "help": "Show only GPS/location data."},
            {"id": "common", "label": "Common Tags Only", "type": "toggle", "flag": "-common",
             "help": "Show only common metadata tags."},
            {"id": "sort", "label": "Sort Output", "type": "toggle", "flag": "-sort",
             "help": "Sort output alphabetically by tag name."},
        ]
    },

    "scrapy_tool": {
        "id": "scrapy_tool",
        "name": "Scrapy",
        "category": "data",
        "description": "Web scraping framework — crawl websites and extract structured data.",
        "icon": "🕸️",
        "executable": "python",
        "script": "-m",
        "module_name": "scrapy",
        "cwd": os.path.join(SUBTOOLS_DIR, "DataExtraction", "scrapy"),
        "args": [
            {"id": "command", "label": "Command", "type": "select", "required": True,
             "options": ["crawl", "fetch", "shell", "view", "list", "genspider"],
             "default": "fetch", "help": "Scrapy command to run.",
             "is_positional": True, "position": 0},
            {"id": "url", "label": "URL / Spider", "type": "text", "required": True,
             "placeholder": "https://example.com", "help": "Target URL or spider name.",
             "is_positional": True, "position": 1},
            {"id": "output", "label": "Output File", "type": "text", "flag": "-o",
             "placeholder": "results.json", "help": "Output file path."},
            {"id": "output_format", "label": "Format", "type": "select", "flag": "-t",
             "options": ["", "json", "jsonlines", "csv", "xml"], "help": "Output format."},
            {"id": "nolog", "label": "Disable Logging", "type": "toggle", "flag": "--nolog",
             "help": "Disable logging output."},
            {"id": "loglevel", "label": "Log Level", "type": "select", "flag": "--loglevel",
             "options": ["", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
             "help": "Log level."},
        ]
    },

    # =========================================================================
    # BUILT-IN TOOLS (run in-process, no subprocess)
    # =========================================================================
    "ip_geolocation": {
        "id": "ip_geolocation",
        "name": "IP Geolocation",
        "category": "builtin",
        "description": "Look up geographic location, ISP, and organization for any IP address.",
        "icon": "📍",
        "builtin": True,
        "args": [
            {"id": "ip", "label": "IP Address", "type": "text", "required": True,
             "placeholder": "8.8.8.8", "help": "IP address to geolocate."},
        ]
    },

    "whois_lookup": {
        "id": "whois_lookup",
        "name": "WHOIS Lookup",
        "category": "builtin",
        "description": "Query domain registration information including registrar, expiration dates, and name servers.",
        "icon": "📋",
        "builtin": True,
        "args": [
            {"id": "domain", "label": "Domain", "type": "text", "required": True,
             "placeholder": "example.com", "help": "Domain name to look up."},
        ]
    },

    "dns_lookup": {
        "id": "dns_lookup",
        "name": "DNS Enumerator",
        "category": "builtin",
        "description": "Resolve and enumerate DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA).",
        "icon": "🔗",
        "builtin": True,
        "args": [
            {"id": "domain", "label": "Domain", "type": "text", "required": True,
             "placeholder": "example.com", "help": "Domain to query DNS records for."},
            {"id": "record_types", "label": "Record Types", "type": "text",
             "placeholder": "A AAAA MX NS TXT CNAME SOA",
             "default": "A AAAA MX NS TXT CNAME SOA",
             "help": "Space-separated DNS record types to query."},
        ]
    },

    "http_headers": {
        "id": "http_headers",
        "name": "HTTP Header Analyzer",
        "category": "builtin",
        "description": "Inspect HTTP response headers for security misconfigurations and server info leaks.",
        "icon": "🔒",
        "builtin": True,
        "args": [
            {"id": "url", "label": "URL", "type": "text", "required": True,
             "placeholder": "https://example.com", "help": "URL to analyze headers from."},
            {"id": "follow_redirects", "label": "Follow Redirects", "type": "toggle",
             "default": True, "help": "Follow HTTP redirects."},
        ]
    },

    "hash_tool": {
        "id": "hash_tool",
        "name": "Hash Identifier & Generator",
        "category": "builtin",
        "description": "Identify unknown hash types and generate MD5, SHA1, SHA256, SHA512 hashes.",
        "icon": "#️⃣",
        "builtin": True,
        "args": [
            {"id": "mode", "label": "Mode", "type": "select", "required": True,
             "options": ["identify", "generate"],
             "default": "identify", "help": "Identify a hash or generate one."},
            {"id": "input_text", "label": "Input", "type": "text", "required": True,
             "placeholder": "hash or text to hash",
             "help": "Hash to identify, or text to generate hashes from."},
        ]
    },

    "subdomain_finder": {
        "id": "subdomain_finder",
        "name": "Subdomain Finder",
        "category": "builtin",
        "description": "Discover subdomains via Certificate Transparency logs (crt.sh).",
        "icon": "🗺️",
        "builtin": True,
        "args": [
            {"id": "domain", "label": "Domain", "type": "text", "required": True,
             "placeholder": "example.com", "help": "Base domain to find subdomains for."},
        ]
    },

    "url_unshortener": {
        "id": "url_unshortener",
        "name": "URL Unshortener",
        "category": "builtin",
        "description": "Follow shortened URL redirect chains to reveal the final destination.",
        "icon": "🔗",
        "builtin": True,
        "args": [
            {"id": "url", "label": "Shortened URL", "type": "text", "required": True,
             "placeholder": "https://bit.ly/abc123", "help": "Short URL to unshorten."},
        ]
    },

    "tech_detector": {
        "id": "tech_detector",
        "name": "Technology Detector",
        "category": "builtin",
        "description": "Detect web technologies, frameworks, and server software from HTTP responses.",
        "icon": "⚙️",
        "builtin": True,
        "args": [
            {"id": "url", "label": "URL", "type": "text", "required": True,
             "placeholder": "https://example.com", "help": "Website URL to analyze."},
        ]
    },
}


def get_tools_by_category():
    """Return tools organized by category."""
    result = {}
    for cat in TOOL_CATEGORIES:
        result[cat["id"]] = {
            "info": cat,
            "tools": {tid: t for tid, t in TOOLS.items() if t["category"] == cat["id"]}
        }
    return result


def get_serializable_tools():
    """Return tools in a JSON-serializable format for the frontend."""
    tools = {}
    for tid, tool in TOOLS.items():
        tools[tid] = {
            "id": tool["id"],
            "name": tool["name"],
            "category": tool["category"],
            "description": tool["description"],
            "icon": tool["icon"],
            "builtin": tool.get("builtin", False),
            "requires_api_key": tool.get("requires_api_key"),
            "args": tool["args"],
        }
    return {
        "categories": TOOL_CATEGORIES,
        "tools": tools,
    }
