
# Log Analysis Tool

This is a Python-based tool designed to analyze server log files and provide valuable insights into web traffic patterns, frequently accessed endpoints, and suspicious activities, such as failed login attempts. It helps administrators and security professionals to easily monitor their systems and detect potential threats.

## Features

- **Requests per IP Address**: Identifies how many requests each IP address made.
- **Most Frequently Accessed Endpoint**: Identifies which endpoint (e.g., URL) is accessed the most frequently.
- **Suspicious Activity Detection**: Detects failed login attempts (HTTP status `401` or "Invalid credentials" messages) and flags IP addresses that exceed a predefined threshold.
- **CSV Output**: The results are saved to a CSV file for further analysis and reporting.

## Requirements

- Python 3.x
- No external libraries are required for the basic functionality. The script uses built-in Python libraries such as `re`, `csv`, and `collections`.

## Usage

1. Clone the repository or download the Python script.

    ```bash
    git clone https://github.com/your-repository/log-analysis.git
    cd log-analysis
    ```

2. Place your server log file in the same directory as the script or provide the path to it in the script.

3. Run the script:

    ```bash
    python3 main.py
    ```

4. The script will read the log file, analyze the data, and display the following:

    - Requests per IP Address
    - The most frequently accessed endpoint
    - Suspicious activities based on failed login attempts

5. The results will be saved to a CSV file named `log_analysis_results.csv` for easy reference.

## Example Output

```bash
Requests per IP Address:
IP Address          Request Count
203.0.113.5         8
198.51.100.23       8
192.168.1.1         7
10.0.0.2            6
192.168.1.100       5

Most Frequently Accessed Endpoint:
/login (Accessed 13 times)

Suspicious Activity Detected:
IP Address          Failed Login Attempts
203.0.113.5         4
192.168.1.100       4

Results saved to log_analysis_results.csv
```

## Output CSV File

The generated `log_analysis_results.csv` will have the following structure:

```
IP Address, Request Count
203.0.113.5, 8
198.51.100.23, 8
192.168.1.1, 7
10.0.0.2, 6
192.168.1.100, 5

Most Accessed Endpoint, Access Count
/login, 13

IP Address, Failed Login Count
203.0.113.5, 4
192.168.1.100, 4
```

## Configuration

- **FAILED_LOGIN_THRESHOLD**: The threshold for failed login attempts that will be flagged as suspicious. It is set to 10 by default. You can modify this in the script as needed.
  
    ```python
    FAILED_LOGIN_THRESHOLD = 10
    ```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

1. Fork the repository.
2. Create a new branch (`git checkout -b feature-name`).
3. Commit your changes (`git commit -am 'Add new feature'`).
4. Push to the branch (`git push origin feature-name`).
5. Create a new pull request.

## Acknowledgements

- The script uses basic Python modules like `csv`, `re`, and `collections.Counter` for log parsing and data manipulation.
- Thank you to [yourname] for creating this tool.

---

### Key Benefits

- **Security Monitoring**: Automatically flags suspicious activity to help administrators take timely action.
- **Ease of Use**: Simple setup and usage. Just provide a log file, and the tool does the rest.
- **Actionable Insights**: Identifies trends in web traffic and potential security vulnerabilities.

