package main

import (
	"bufio"
	"fmt"
	"github.com/frida/frida-go/frida"
	"os"
)

var script = `
console.log("[*] Starting script");
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

	localDev, err := mgr.USBDevice()
	if err != nil {
		fmt.Println("Could not get local device: ", err)
		// Let's exit here because there is no point to do anything with nonexistent device
		os.Exit(1)
	}

	fmt.Println("[*] Chosen device: ", localDev.Name())

	var appName = "AppName"
	fmt.Println("[*] Attaching to " + appName)
	session, err := localDev.Attach(appName, nil)
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
