# VizMap

VizMap is a Python script designed to parse and visualize Nmap XML output in a matrix format. It allows users to filter and display information about hosts, services, and open ports detected by Nmap scans. This tool is particularly useful for quickly identifying specific services or operating systems across a network scan.

## Features

- **OS Filtering**: Filter hosts based on their detected operating systems (e.g., Windows).
- **Protocol Filtering**: Focus on hosts with specific open ports (e.g., FTP, SSH, HTTP).
- **SQL Service Detection**: Automatically detect common SQL services like MSSQL, MySQL, PostgreSQL, and more.
- **Custom Port Filtering**: Specify a custom port to filter hosts.
- **ANSI Color Support**: Colored output to differentiate between open and filtered ports.

## Requirements

- Python 3.x
- [PrettyTable](https://pypi.org/project/prettytable/)
- [Colorama](https://pypi.org/project/colorama/)

Install the required Python packages using pip:

```bash
pip install prettytable colorama
```

## Usage
```bash
python vizmap.py <nmap_output.xml> [options]
```

## Example Output
```bash
+-------------+-----------------+---------------------+----+----+----+----+-----+-----+------+------+------+------+
| 192.168.1.1 |   router.local  |     Linux 2.6.32    |    | 22 |    | 80 | 443 |     |      |      |      |      |
| 192.168.1.2 | webserver.local | Windows Server 2016 | 21 |    | 25 |    |     |     |      |      | 3306 |      |
| 192.168.1.3 |  dbserver.local |      Windows 10     |    |    |    |    |     | 445 | 1433 | 1434 |      | 3389 |
+-------------+-----------------+---------------------+----+----+----+----+-----+-----+------+------+------+------+
```

## 🤝 Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.