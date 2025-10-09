package main

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

const (
	fileReadData   = 0x0001
	fileWriteData  = 0x0002
	fileAppendData = 0x0004
	fileReadEA     = 0x0008
	fileWriteEA    = 0x0010
	fileReadAttr   = 0x0080
	fileWriteAttr  = 0x0100
	readControl    = 0x20000
	synchronize    = 0x100000
	processVmOp    = 0x0008
	processVmRead  = 0x0010
	processVmWrite = 0x0020

	statusMismatch = 0xC0000004
	statusSuccess  = 0x00000000
	queryInfo      = 0x0400
	dupHandle      = 0x0040
	handleClass    = 51
	typeClass      = 2
	dosPath        = 0
	diskType       = 1
	createAlways   = 2
	normalAttr     = 0x80
	procSnapshot   = 0x00000002

	fileStandardInfo = 5
	filePositionInfo = 14

	maxPath         = 32768
	fileOpenIf      = 3
	fileSyncIoAlert = 0x00000010
)

type Handle struct {
	Val    syscall.Handle
	Refs   uintptr
	Ptrs   uintptr
	Rights uint32
	Type   uint32
	Flags  uint32
	_      uint32
}

type Snapshot struct {
	Total uintptr
	_     uintptr
}

type ObjType struct {
	Name  WideStr
	Count uint32
	Total uint32
}

type WideStr struct {
	Size  uint16
	MaxSz uint16
	Data  *uint16
}

type ProcInfo struct {
	Sz     uint32
	_      uint32
	Id     uint32
	Heap   uintptr
	Mod    uint32
	Thds   uint32
	Parent uint32
	Base   int32
	Attrs  uint32
	Name   [260]byte
}

type IoStatusBlock struct {
	Status uintptr
	Info   uintptr
}

type FileStandardInfo struct {
	AllocationSize int64
	EndOfFile      int64
	NumberOfLinks  uint32
	DeletePending  byte
	Directory      byte
}

type FilePositionInfo struct {
	CurrentByteOffset int64
}

type ObjectAttributes struct {
	Length                   uint32
	RootDirectory            syscall.Handle
	ObjectName               *WideStr
	Attributes               uint32
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

type winAPI struct {
	queryProcess    *syscall.LazyProc
	queryObject     *syscall.LazyProc
	closeHandle     *syscall.LazyProc
	readFile        *syscall.LazyProc
	queryFileInfo   *syscall.LazyProc
	setFileInfo     *syscall.LazyProc
	duplicateObject *syscall.LazyProc
	openProcess     *syscall.LazyProc
	createFile      *syscall.LazyProc
	writeFile       *syscall.LazyProc
	createThread    *syscall.LazyProc
	createSnapshot  *syscall.LazyProc
	nextProcess     *syscall.LazyProc
	getFilePath     *syscall.LazyProc
	getFileType     *syscall.LazyProc
}

var api = &winAPI{
	queryProcess:    syscall.NewLazyDLL("ntdll.dll").NewProc("NtQueryInformationProcess"),
	queryObject:     syscall.NewLazyDLL("ntdll.dll").NewProc("NtQueryObject"),
	closeHandle:     syscall.NewLazyDLL("ntdll.dll").NewProc("NtClose"),
	readFile:        syscall.NewLazyDLL("ntdll.dll").NewProc("NtReadFile"),
	queryFileInfo:   syscall.NewLazyDLL("ntdll.dll").NewProc("NtQueryInformationFile"),
	setFileInfo:     syscall.NewLazyDLL("ntdll.dll").NewProc("NtSetInformationFile"),
	duplicateObject: syscall.NewLazyDLL("ntdll.dll").NewProc("NtDuplicateObject"),
	openProcess:     syscall.NewLazyDLL("ntdll.dll").NewProc("NtOpenProcess"),
	createFile:      syscall.NewLazyDLL("ntdll.dll").NewProc("NtCreateFile"),
	writeFile:       syscall.NewLazyDLL("ntdll.dll").NewProc("NtWriteFile"),
	createThread:    syscall.NewLazyDLL("ntdll.dll").NewProc("RtlCreateUserThread"),
	createSnapshot:  syscall.NewLazyDLL("kernel32.dll").NewProc("CreateToolhelp32Snapshot"),
	nextProcess:     syscall.NewLazyDLL("kernel32.dll").NewProc("Process32Next"),
	getFilePath:     syscall.NewLazyDLL("kernel32.dll").NewProc("GetFinalPathNameByHandleW"),
	getFileType:     syscall.NewLazyDLL("kernel32.dll").NewProc("GetFileType"),
}

func ScanProcesses(target string) (map[uint32][]Handle, error) {
	procs := make(map[uint32][]Handle)

	h, _, err := api.createSnapshot.Call(uintptr(procSnapshot), 0)
	if h == 0 || h == ^uintptr(0) {
		return nil, fmt.Errorf("snapshot failed: %v", err)
	}
	defer api.closeHandle.Call(h)

	info := ProcInfo{Sz: uint32(unsafe.Sizeof(ProcInfo{}))}

	for {
		if ok, _, _ := api.nextProcess.Call(h, uintptr(unsafe.Pointer(&info))); ok == 0 {
			break
		}

		var name string
		for i, c := range info.Name {
			if c == 0 {
				name = string(info.Name[:i])
				break
			}
		}

		if !strings.EqualFold(name, target) {
			continue
		}

		var clientId struct {
			pid uintptr
			tid uintptr
		}
		clientId.pid = uintptr(info.Id)

		var objAttr ObjectAttributes
		objAttr.Length = uint32(unsafe.Sizeof(objAttr))

		var proc syscall.Handle
		if r, _, _ := api.openProcess.Call(
			uintptr(unsafe.Pointer(&proc)),
			uintptr(queryInfo|dupHandle),
			uintptr(unsafe.Pointer(&objAttr)),
			uintptr(unsafe.Pointer(&clientId)),
		); r != statusSuccess {
			continue
		}

		var bufLen uint32
		var mem []byte
		code := uint32(statusMismatch)

		for code == statusMismatch {
			var p uintptr
			if bufLen > 0 {
				mem = make([]byte, bufLen)
				p = uintptr(unsafe.Pointer(&mem[0]))
			}

			r, _, _ := api.queryProcess.Call(uintptr(proc), handleClass, p, uintptr(bufLen), uintptr(unsafe.Pointer(&bufLen)))
			code = uint32(r)
		}

		if code == statusSuccess && bufLen >= uint32(unsafe.Sizeof(Snapshot{})) {
			snap := (*Snapshot)(unsafe.Pointer(&mem[0]))
			n := snap.Total

			if n > 0 && bufLen >= uint32(unsafe.Sizeof(Snapshot{})+uintptr(n)*unsafe.Sizeof(Handle{})) {
				off := unsafe.Sizeof(Snapshot{})
				items := make([]Handle, n)
				for i := uintptr(0); i < n; i++ {
					src := (*Handle)(unsafe.Pointer(uintptr(unsafe.Pointer(&mem[0])) + off + i*unsafe.Sizeof(Handle{})))
					items[i] = *src
				}
				procs[info.Id] = items
			}
		}

		api.closeHandle.Call(uintptr(proc))
	}

	return procs, nil
}

func ExtractFile(hnd syscall.Handle, owner uint32, pattern string) ([]byte, string, error) {
	var clientId struct {
		pid uintptr
		tid uintptr
	}
	clientId.pid = uintptr(owner)

	var objAttr ObjectAttributes
	objAttr.Length = uint32(unsafe.Sizeof(objAttr))

	var proc syscall.Handle
	if r, _, _ := api.openProcess.Call(
		uintptr(unsafe.Pointer(&proc)),
		uintptr(dupHandle),
		uintptr(unsafe.Pointer(&objAttr)),
		uintptr(unsafe.Pointer(&clientId)),
	); r != statusSuccess {
		return nil, "", fmt.Errorf("access denied")
	}
	defer api.closeHandle.Call(uintptr(proc))

	var dup syscall.Handle
	self := ^uintptr(0) // this is called pseudohandle for current process (-1)

	accessRights := fileReadData | fileWriteData | fileAppendData | fileReadEA | fileWriteEA | fileReadAttr | fileWriteAttr | readControl | synchronize
	if r, _, _ := api.duplicateObject.Call(uintptr(proc), uintptr(hnd), self, uintptr(unsafe.Pointer(&dup)), uintptr(accessRights), 0, 0); r != statusSuccess {
		return nil, "", fmt.Errorf("dup error: %x", r)
	}
	defer api.closeHandle.Call(uintptr(dup))

	var bufLen uint32
	var mem []byte
	code := uint32(statusMismatch)

	for code == statusMismatch {
		var p uintptr
		if bufLen > 0 {
			mem = make([]byte, bufLen)
			p = uintptr(unsafe.Pointer(&mem[0]))
		}

		r, _, _ := api.queryObject.Call(uintptr(dup), typeClass, p, uintptr(bufLen), uintptr(unsafe.Pointer(&bufLen)))
		code = uint32(r)
	}

	if code != statusSuccess {
		return nil, "", fmt.Errorf("query failed: %x", code)
	}

	obj := (*ObjType)(unsafe.Pointer(&mem[0]))
	if obj.Name.Data == nil {
		return nil, "", fmt.Errorf("no name")
	}

	sz := int(obj.Name.Size / 2)
	if sz > 256 {
		sz = 256
	}
	buf := (*[256]uint16)(unsafe.Pointer(obj.Name.Data))[:sz:sz]
	kind := syscall.UTF16ToString(buf)

	if kind != "File" {
		return nil, "", fmt.Errorf("wrong type: %s", kind)
	}

	if t, _, _ := api.getFileType.Call(uintptr(dup)); t != diskType {
		return nil, "", fmt.Errorf("not disk file")
	}

	pathbuf := make([]uint16, maxPath)
	r, _, _ := api.getFilePath.Call(uintptr(dup), uintptr(unsafe.Pointer(&pathbuf[0])), uintptr(len(pathbuf)), dosPath)
	if r == 0 {
		return nil, "", fmt.Errorf("path error")
	}

	fullpath := syscall.UTF16ToString(pathbuf)

	sep := strings.LastIndex(fullpath, "\\")
	if sep == -1 {
		sep = strings.LastIndex(fullpath, "/")
	}

	var basename string
	if sep == -1 {
		basename = fullpath
	} else {
		basename = fullpath[sep+1:]
	}

	if !strings.EqualFold(basename, pattern) {
		return nil, "", fmt.Errorf("no match: got %s, want %s", basename, pattern)
	}

	var stdInfo FileStandardInfo
	var iosb IoStatusBlock

	if r, _, _ := api.queryFileInfo.Call(uintptr(dup), uintptr(unsafe.Pointer(&iosb)), uintptr(unsafe.Pointer(&stdInfo)), unsafe.Sizeof(stdInfo), fileStandardInfo); r != statusSuccess {
		return nil, fullpath, fmt.Errorf("size error: %x", r)
	}

	fsz := stdInfo.EndOfFile
	if fsz == 0 {
		return []byte{}, fullpath, nil
	}

	var posInfo FilePositionInfo
	posInfo.CurrentByteOffset = 0
	api.setFileInfo.Call(uintptr(dup), uintptr(unsafe.Pointer(&iosb)), uintptr(unsafe.Pointer(&posInfo)), unsafe.Sizeof(posInfo), filePositionInfo)

	content := make([]byte, fsz)
	iosb = IoStatusBlock{}

	if r, _, _ := api.readFile.Call(uintptr(dup), 0, 0, 0, uintptr(unsafe.Pointer(&iosb)), uintptr(unsafe.Pointer(&content[0])), uintptr(fsz), 0, 0); r != statusSuccess {
		return nil, fullpath, fmt.Errorf("read error: %x", r)
	}

	return content[:iosb.Info], fullpath, nil
}

func SaveFile(content []byte, dest string) error {
	var abspath string
	if len(dest) >= 2 && dest[1] == ':' {
		abspath = dest
	} else {
		cwd := make([]uint16, 260)
		getCwd := syscall.NewLazyDLL("kernel32.dll").NewProc("GetCurrentDirectoryW")
		n, _, _ := getCwd.Call(uintptr(len(cwd)), uintptr(unsafe.Pointer(&cwd[0])))
		if n == 0 {
			return fmt.Errorf("failed to get current directory")
		}
		cwdStr := syscall.UTF16ToString(cwd)
		abspath = cwdStr + "\\" + dest
	}

	abspath = "\\??\\" + abspath

	path16, err := syscall.UTF16FromString(abspath)
	if err != nil {
		return err
	}

	var ustr WideStr
	ustr.Size = uint16((len(path16) - 1) * 2)
	ustr.MaxSz = ustr.Size + 2
	ustr.Data = &path16[0]

	var objAttr ObjectAttributes
	objAttr.Length = uint32(unsafe.Sizeof(objAttr))
	objAttr.ObjectName = &ustr
	objAttr.Attributes = 0x40 // obj_case_insensitive

	var iosb IoStatusBlock
	var h syscall.Handle

	r, _, _ := api.createFile.Call(
		uintptr(unsafe.Pointer(&h)),
		uintptr(fileWriteData|fileAppendData|synchronize),
		uintptr(unsafe.Pointer(&objAttr)),
		uintptr(unsafe.Pointer(&iosb)),
		0, 
		normalAttr,
		0,          // shareAccess
		5,          // file_overwrite_if
		0x00000020, // file_synchronous_io_nonalert
		0,
		0,
	)

	if r != statusSuccess {
		return fmt.Errorf("failed to create file: %x", r)
	}
	defer api.closeHandle.Call(uintptr(h))

	iosb = IoStatusBlock{}

	r, _, _ = api.writeFile.Call(
		uintptr(h),
		0, // event
		0, // apcroutine
		0, // apccontext 
		uintptr(unsafe.Pointer(&iosb)),
		uintptr(unsafe.Pointer(&content[0])),
		uintptr(len(content)),
		0, // byteoffset
		0, // key
	)

	if r != statusSuccess {
		return fmt.Errorf("failed to write file: %x", r)
	}

	return nil
}

func KillHandle(owner uint32, hnd syscall.Handle) error {
	var clientId struct {
		pid uintptr
		tid uintptr
	}
	clientId.pid = uintptr(owner)

	var objAttr ObjectAttributes
	objAttr.Length = uint32(unsafe.Sizeof(objAttr))

	var proc syscall.Handle
	// Need process_create_thread (0x0002) for rtlcreateuserthread
	processCreateThread := uint32(0x0002)
	if r, _, _ := api.openProcess.Call(
		uintptr(unsafe.Pointer(&proc)),
		uintptr(dupHandle|processVmOp|processVmRead|processVmWrite|processCreateThread),
		uintptr(unsafe.Pointer(&objAttr)),
		uintptr(unsafe.Pointer(&clientId)),
	); r != statusSuccess {
		return fmt.Errorf("failed to open process: %x", r)
	}
	defer api.closeHandle.Call(uintptr(proc))

	fn := api.closeHandle.Addr()
	var thd syscall.Handle

	// Use RtlCreateUserThread
	// params: Process, SecurityDescriptor, CreateSuspended, StackZeroBits,
	// StackReserved, StackCommit, StartAddress, Parameter, Thread, ClientId
	r, _, _ := api.createThread.Call(
		uintptr(proc),
		0,            // securydescritpor
		0,            // createsuspnended
		0,            // stackzerobits
		0,            // stackreserved
		0,            // stackcommit
		fn,           // startaddr (NtClose)
		uintptr(hnd), // param
		uintptr(unsafe.Pointer(&thd)),
		0, // clientid
	)

	if r != statusSuccess {
		return fmt.Errorf("failed to create remote thread: %x", r)
	}

	api.closeHandle.Call(uintptr(thd))
	return nil
}
