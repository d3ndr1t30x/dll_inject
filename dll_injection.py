import ctypes
import sys
import os

# Constants for process access rights
PROCESS_ALL_ACCESS = 0x1F0FFF

# Constants for memory allocation
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_EXECUTE_READWRITE = 0x40

# Define necessary Windows API functions
kernel32 = ctypes.windll.kernel32

def inject_dll(pid, dll_path):
    # Open the target process with all access rights
    process_handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not process_handle:
        print(f"Failed to open process {pid}.")
        return False

    # Allocate memory in the target process for the DLL path
    dll_path_buffer = ctypes.create_string_buffer(dll_path.encode('utf-8'))
    dll_path_len = len(dll_path_buffer)
    remote_memory = kernel32.VirtualAllocEx(process_handle, None, dll_path_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    if not remote_memory:
        print("Failed to allocate memory in target process.")
        kernel32.CloseHandle(process_handle)
        return False

    # Write the DLL path into the allocated memory
    bytes_written = ctypes.c_size_t(0)
    if not kernel32.WriteProcessMemory(process_handle, remote_memory, dll_path_buffer, dll_path_len, ctypes.byref(bytes_written)):
        print("Failed to write to target process memory.")
        kernel32.VirtualFreeEx(process_handle, remote_memory, 0, MEM_RELEASE)
        kernel32.CloseHandle(process_handle)
        return False

    # Get the address of LoadLibraryA function
    load_library_addr = kernel32.GetProcAddress(kernel32.GetModuleHandleA(b"kernel32.dll"), b"LoadLibraryA")
    if not load_library_addr:
        print("Failed to get LoadLibraryA address.")
        kernel32.VirtualFreeEx(process_handle, remote_memory, 0, MEM_RELEASE)
        kernel32.CloseHandle(process_handle)
        return False

    # Create a remote thread in the target process to execute LoadLibraryA with the DLL path
    thread_handle = kernel32.CreateRemoteThread(process_handle, None, 0, load_library_addr, remote_memory, 0, None)
    if not thread_handle:
        print("Failed to create remote thread.")
        kernel32.VirtualFreeEx(process_handle, remote_memory, 0, MEM_RELEASE)
        kernel32.CloseHandle(process_handle)
        return False

    # Wait for the remote thread to complete
    kernel32.WaitForSingleObject(thread_handle, 0xFFFFFFFF)

    # Clean up: free allocated memory and close handles
    kernel32.VirtualFreeEx(process_handle, remote_memory, 0, MEM_RELEASE)
    kernel32.CloseHandle(thread_handle)
    kernel32.CloseHandle(process_handle)

    print(f"Successfully injected DLL into process {pid}.")
    return True

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {os.path.basename(__file__)} <PID> <DLL Path>")
        sys.exit(1)

    pid = int(sys.argv[1])
    dll_path = sys.argv[2]

    if not os.path.isfile(dll_path):
        print("Invalid DLL path.")
        sys.exit(1)

    if not inject_dll(pid, dll_path):
        sys.exit(1)
