<!-- 
# SOCKS V5 server

![Platform](https://img.shields.io/badge/platform-linux-brightgreen)
![License](https://img.shields.io/github/license/totravel/socks5-server-c)
![Lines of code](https://img.shields.io/tokei/lines/github/totravel/socks5-server-c)
![GitHub repo size](https://img.shields.io/github/repo-size/totravel/socks5-server-c)
![GitHub last commit](https://img.shields.io/github/last-commit/totravel/socks5-server-c)
![Travis (.com) branch](https://img.shields.io/travis/com/totravel/socks5-server-c/master)

A fresh implementation of SOCKS V5 server in C. -->

<h1 align="center">SOCKS V5 server</h1>

<p align="center">
  <img alt="Platform" src="https://img.shields.io/badge/platform-linux-brightgreen">
  <img alt="License" src="https://img.shields.io/github/license/totravel/socks5-server-c">
  <!-- <img alt="GitHub repo size" src="https://img.shields.io/github/repo-size/totravel/socks5-server-c"> -->
  <img alt="Lines of code" src="https://img.shields.io/tokei/lines/github/totravel/socks5-server-c">
  <img alt="GitHub code size in bytes" src="https://img.shields.io/github/languages/code-size/totravel/socks5-server-c">
  <img alt="GitHub last commit" src="https://img.shields.io/github/last-commit/totravel/socks5-server-c">
  <img alt="Travis (.com) branch" src="https://img.shields.io/travis/com/totravel/socks5-server-c/master">
</p>

<p align="center">一个简易的 SOCKS V5 代理服务器。</p>

## Features

- 支持 TCP 代理和 UDP 代理
- 支持代理 DNS 查询
- 支持用户名密码认证方式

## Build

使用 `make` 完成编译和链接。

```bash
$ make
```

若跟上 `CFLAG=-DDEBUG` 则开启调试模式：

```bash
$ make CFLAG=-DDEBUG
```

## Usage

不带任何选项启动，则监听 1080 端口，无需认证。

```bash
$ ./server
NO AUTHENTICATION REQUIRED
Listening at 0.0.0.0:1080
```

带上 `-h` 选项则显示帮助信息。

```bash
$ ./server -h
usage: ./server [options]
options: 
  -a <address>         Local Address to bind (default: 0.0.0.0).
  -p <port>            Port number to bind (default: 1080).
  -u <path/to/passwd>  The path to passwd.
  -d                   Run as a daemon.
  -h                   Show this help message.
```

选项 `-a` 和 `-p` 分别用来指定服务器绑定的 IP 地址和端口号。

```bash
$ ./server -a 127.0.0.1 -p 8080
NO AUTHENTICATION REQUIRED
Listening at 127.0.0.1:8080
```

选项 `-u` 用于开启用户名密码认证方式，选项后面必须跟上一个文件的路径。该文件的每一行对应一个用户，用户名和密码之间用逗号 `,` 隔开，例如：

```bash
$ cat ./passwd
user1,123456
user2,666
user3,2333
$ ./server -u ./passwd
USERNAME/PASSWORD
3 users
Listening at 0.0.0.0:1080
```

若带上 `-d` 参数，服务器将脱离终端，成为守护进程。

```bash
$ ./server -d
NO AUTHENTICATION REQUIRED
Listening at 0.0.0.0:1080
PID is [xxxxx]
$ netstat -ntlp | grep xxxxx
tcp        0      0 0.0.0.0:1080                0.0.0.0:*                   LISTEN      xxxxx/./server
```

## License

本项目采用 [MIT](https://opensource.org/licenses/MIT) 开源许可协议。

```
MIT License

Copyright (c) 2019-2021 totravel

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
