# frida-go
Go bindings for frida.

For the documentation, visit [https://pkg.go.dev/github.com/frida/frida-go/frida](https://pkg.go.dev/github.com/frida/frida-go/frida).

# Installation
* `GO111MODULE` needs to be set to `on` or `auto`.
* Download the _frida-core-devkit_ from the Frida releases [page](https://github.com/frida/frida/releases/) for you operating system and architecture.
* Extract the downloaded archive
* Copy _frida-core.h_ inside your systems include directory(inside /usr/local/include/) and _libfrida-core.a_ inside your lib directory (usually /usr/local/lib).

To use in your project, just execute:
```bash
$ go get github.com/frida/frida-go/frida@latest
```

Supported OS:
- [x] MacOS
- [x] Linux
- [x] Android
- [ ] Windows

# Small example
```golang
package main

import (
  "bufio"
  "fmt"
  "github.com/frida/frida-go/frida"
  "os"
)

var script = `
Interceptor.attach(Module.getExportByName(null, 'open'), {
	onEnter(args) {
		const what = args[0].readUtf8String();
		console.log("[*] open(" + what + ")");
	}
});
Interceptor.attach(Module.getExportByName(null, 'close'), {
	onEnter(args) {
		console.log("close called");
	}
});
`

func main() {
  mgr := frida.NewDeviceManager()

  devices, err := mgr.EnumerateDevices()
  if err != nil {
    panic(err)
  }

  for _, d := range devices {
    fmt.Println("[*] Found device with id:", d.ID())
  }

  localDev, err := mgr.LocalDevice()
  if err != nil {
    fmt.Println("Could not get local device: ", err)
    // Let's exit here because there is no point to do anything with nonexistent device
    os.Exit(1)
  }

  fmt.Println("[*] Chosen device: ", localDev.Name())

  fmt.Println("[*] Attaching to Telegram")
  session, err := localDev.Attach("Telegram", nil)
  if err != nil {
	  fmt.Println("Error occurred attaching:", err)
	  os.Exit(1)
  }

  script, err := session.CreateScript(script)
  if err != nil {
    fmt.Println("Error occurred creating script:", err)
	os.Exit(1)
  }

  script.On("message", func(msg string) {
    fmt.Println("[*] Received", msg)
  })

  if err := script.Load(); err != nil {
    fmt.Println("Error loading script:", err)
    os.Exit(1)
  }

  r := bufio.NewReader(os.Stdin)
  r.ReadLine()
}

```

Build and run it, output will look something like this:
```bash
$ go build example.go && ./example
[*] Found device with id: local
[*] Found device with id: socket
[*] Chosen device:  Local System
[*] Attaching to Telegram
[*] Received {"type":"log","level":"info","payload":"[*] open(/Users/daemon1/Library/Application Support/Telegram Desktop/tdata/user_data/cache/0/25/0FDE3ED70BCA)"}
[*] Received {"type":"log","level":"info","payload":"[*] open(/Users/daemon1/Library/Application Support/Telegram Desktop/tdata/user_data/cache/0/8E/FD728183E115)"}
```


## download frida-core mingw     binary
打开frida的action页面，里面找到对应的job id，点击进去，查看对应的log，找到mingw devkit upload里面下载
https://github.com/frida/frida-core/actions/runs/14932605596/job/41952404276
放入你的项目目录下的frida-core目录下


how to build exameple/main.go，先添项目临时环境变量，然后再编译
goland 编译选项增加环境变量
windows   CGO_CFLAGS=-IF:\go_workspace\webkit-debug\inspector-web\frida-core\windows-x86_64;CGO_LDFLAGS=-LF:\go_workspace\webkit-debug\inspector-web\frida-core\windows-x86_64
mac   CGO_CFLAGS=-IF:\go_workspace\webkit-debug\inspector-web\frida-core\macos-x86_64;CGO_LDFLAGS=-LF:\go_workspace\webkit-debug\inspector-web\frida-core\macos-x86_64

如果是命令行则
set CGO_CFLAGS=-IF:\go_workspace\frida-go-test\frida-core\windows-x86_64
set CGO_LDFLAGS=-LF:\go_workspace\frida-go-test\frida-core\windows-x86_64


```bash
set CGO_CFLAGS=-IF:\go_workspace\frida-go-test\frida-core\windows-x86_64
set CGO_LDFLAGS=-LF:\go_workspace\frida-go-test\frida-core\windows-x86_64
go build main.go
```
尝试下面命令但是并没成功
```bash
go build -x  -ldflags="-L ${SRCDIR}/frida-core" -gcflags="-I ${SRCDIR}/frida-core" main.go
```


ref:https://github.com/pk5ls20/frida-go/tree/feat/support-windows