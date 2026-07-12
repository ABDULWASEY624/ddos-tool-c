 HEAVY DDoS ENGINE v3.0                           
         For Authorized Security Testing Only

## ⚠️ Disclaimer

This tool is intended **strictly for educational and authorized testing purposes only**.

* Do **NOT** use this tool against systems, servers, or networks without **explicit permission**.
* Unauthorized usage may violate laws and regulations in your country.
* The developer is **not responsible** for any misuse or damage caused by this software.

## 🚀 Features

* High-performance network request generation
* Multi-threaded architecture
* Configurable target, port, and request rate
* Lightweight and minimal dependencies
* Designed for learning low-level networking in C

## 🛠️ Requirements

* GCC or any C compiler
* Linux (recommended) or Unix-like system

## 📦 Installation

```bash
git clone https://github.com/ABDULWASEY624/ddos-tool-c
cd ddos-tool-c
do cmd : Make
```

## ▶️ Usage

```
./ddos <target> <port> <threads> <duration> <mode> [options]

  ```
### Example:

```bash

    sudo ./ddos 1.2.3.4 80 500 60 http --domain=example.com --cf-bypass
    sudo ./ddos 1.2.3.4 443 1000 0 http --proxies=proxies.txt --persistent
    sudo ./ddos 1.2.3.4 80 200 120 syn --spoof
    
```

## 📚 Educational Purpose

This project is useful for learning:

* Socket programming in C
* Multi-threading (pthreads)
* Network behavior under load
* Performance optimization techniques

## 🤝 Contributing

Pull requests are welcome. Feel free to improve performance, add features, or fix bugs.

## 📄 License

This project is licensed under the MIT License.

---

**Remember:** Always test responsibly and only on systems you own or have permission to test.
