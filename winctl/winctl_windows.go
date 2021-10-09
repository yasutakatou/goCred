package winctl

import (
	"fmt"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

type (
	HANDLE uintptr
	HWND   HANDLE
)

type RECTdata struct {
	Left   int32
	Top    int32
	Right  int32
	Bottom int32
}

var (
	user32                  = syscall.MustLoadDLL("user32.dll")
	procEnumWindows         = user32.MustFindProc("EnumWindows")
	procGetWindowTextW      = user32.MustFindProc("GetWindowTextW")
	procSetActiveWindow     = user32.MustFindProc("SetActiveWindow")
	procSetForegroundWindow = user32.MustFindProc("SetForegroundWindow")
	procGetForegroundWindow = user32.MustFindProc("GetForegroundWindow")
	procGetWindowRect       = user32.MustFindProc("GetWindowRect")
)

func ListWindow(Debug bool) []string {
	var rect RECTdata

	ret := []string{}

	cb := syscall.NewCallback(func(h syscall.Handle, p uintptr) uintptr {
		b := make([]uint16, 200)
		_, err := GetWindowText(h, &b[0], int32(len(b)))
		if err != nil {
			return 1
		}

		GetWindowRect(HWND(h), &rect, Debug)
		if rect.Left != 0 || rect.Top != 0 || rect.Right != 0 || rect.Bottom != 0 {
			if Debug == true {
				fmt.Printf("Window Title '%s' window: handle=0x%x\n", syscall.UTF16ToString(b), h)
				if rect.Left != 0 || rect.Top != 0 || rect.Right != 0 || rect.Bottom != 0 {
					fmt.Printf("window rect: ")
					fmt.Println(rect)
				}
			}
			ret = append(ret, fmt.Sprintf("%s : %x", syscall.UTF16ToString(b), h))
		}
		return 1
	})
	EnumWindows(cb, 0)
	return ret
}

func matchCheck(stra, strb string) bool {
	if strings.Index(strb, stra) != -1 {
		return true
	} else {
		if strings.Index(stra, strb) != -1 {
			return true
		}
	}
	return false
}

func FocusWindow(title string, Debug bool) uintptr {
	var hwnd syscall.Handle
	var rect RECTdata

	cb := syscall.NewCallback(func(h syscall.Handle, p uintptr) uintptr {
		b := make([]uint16, 200)
		_, err := GetWindowText(h, &b[0], int32(len(b)))
		if err != nil {
			return 1
		}

		if Debug == true {
			fmt.Printf("EnumWindows Search '%s' window: handle=0x%x\n", syscall.UTF16ToString(b), h)
		}

		if matchCheck(title, syscall.UTF16ToString(b)) == true {
			if Debug == true {
				fmt.Printf("Found! window: '%s' handle=0x%x\n", syscall.UTF16ToString(b), h)
			}
			GetWindowRect(HWND(h), &rect, Debug)
			if int(rect.Right-rect.Left) > 0 && int(rect.Bottom-rect.Top) > 0 {
				hwnd = h
				return 0
			}
		}
		return 1
	})
	EnumWindows(cb, 0)
	return uintptr(hwnd)
}

func GetWindow(funcName string, Debug bool) uintptr {
	hwnd, _, _ := syscall.Syscall(procGetForegroundWindow.Addr(), 6, 0, 0, 0)
	if Debug == true {
		fmt.Printf("currentWindow: handle=0x%x.\n", hwnd)
	}
	return hwnd
}

func SetActiveWindow(hwnd HWND, Debug bool) {
	if Debug == true {
		fmt.Printf("SetActiveWindow: handle=0x%x.\n", hwnd)
	}
	syscall.Syscall(procSetActiveWindow.Addr(), 4, uintptr(hwnd), 0, 0)
	syscall.Syscall(procSetForegroundWindow.Addr(), 5, uintptr(hwnd), 0, 0)
}

func GetWindowRect(hwnd HWND, rect *RECTdata, Debug bool) (err error) {
	r1, _, e1 := syscall.Syscall(procGetWindowRect.Addr(), 7, uintptr(hwnd), uintptr(unsafe.Pointer(rect)), 0)
	if r1 == 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func GetWindowText(hwnd syscall.Handle, str *uint16, maxCount int32) (len int32, err error) {
	r0, _, e1 := syscall.Syscall(procGetWindowTextW.Addr(), 3, uintptr(hwnd), uintptr(unsafe.Pointer(str)), uintptr(maxCount))
	if len = int32(r0); len == 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func EnumWindows(enumFunc uintptr, lparam uintptr) (err error) {
	r1, _, e1 := syscall.Syscall(procEnumWindows.Addr(), 2, uintptr(enumFunc), uintptr(lparam), 0)
	if r1 == 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func ChangeTarget(setHwnd uintptr, tryCounter, waitSeconds int, Debug bool) bool {
	for {
		if Debug == true {
			fmt.Printf("tryCounter: %d\n", tryCounter)
		}

		if setHwnd != GetWindow("GetForegroundWindow", Debug) {
			SetActiveWindow(HWND(setHwnd), Debug)
		} else {
			return true
		}
		tryCounter = tryCounter - 1
		if tryCounter < 0 {
			return false
		}
		time.Sleep(time.Duration(waitSeconds) * time.Millisecond)
	}
}
