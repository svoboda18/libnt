#include <windows.h>
#include <errno.h>
#include <io.h>
#include <stdio.h>
#include <sys/mman.h>

#ifndef FILE_MAP_EXECUTE
#define FILE_MAP_EXECUTE    0x0020
#endif /* FILE_MAP_EXECUTE */

static int __map_mman_error(const DWORD err) {
	switch (err) {
	case ERROR_ALREADY_EXISTS:
	case ERROR_FILE_EXISTS:
		return EEXIST;
	case ERROR_INVALID_FUNCTION:
		return ENOSYS;
	case ERROR_FILE_NOT_FOUND:
	case ERROR_PATH_NOT_FOUND:
		return ENOENT;
	case ERROR_TOO_MANY_OPEN_FILES:
		return EMFILE;
	case ERROR_INVALID_HANDLE:
		return EBADF;
	case ERROR_NOT_ENOUGH_MEMORY:
	case ERROR_COMMITMENT_LIMIT:
	case ERROR_OUTOFMEMORY:
	case ERROR_NO_SYSTEM_RESOURCES:
		return ENOMEM;
	case ERROR_ACCESS_DENIED:
	case ERROR_INVALID_ACCESS:
	case ERROR_SHARING_VIOLATION:
	case ERROR_LOCK_VIOLATION:
		return EACCES;
	case ERROR_INVALID_DRIVE:
		return ENXIO;
	case ERROR_NOT_SAME_DEVICE:
		return EXDEV;
	case ERROR_NO_MORE_FILES:
		return ENFILE;
	case ERROR_WRITE_PROTECT:
	case ERROR_CANT_OPEN_ANONYMOUS:		/* Can't open anonymous token */
		return EPERM;
	case ERROR_NOT_SUPPORTED:
		return ENOSYS;
	case ERROR_DISK_FULL:
		return ENOSPC;
	case ERROR_BROKEN_PIPE:
	case ERROR_NO_DATA:
		return EPIPE;
	case ERROR_INVALID_NAME:		/* Invalid syntax in filename */
	case ERROR_INVALID_PARAMETER:	/* Invalid function parameter */
	case ERROR_BAD_PATHNAME:		/* Invalid pathname */
		return EINVAL;
	case ERROR_DIRECTORY:			/* "Directory name is invalid" */
		return ENOTDIR;				/* Seems the closest mapping */
	case WSAENOTSOCK:				/* For fstat() calls */
		return ENOTSOCK;
	case ERROR_INVALID_ADDRESS:
	case ERROR_INVALID_USER_BUFFER:
		return EFAULT;
	case ERROR_IO_PENDING:			/* System call "interrupted" by signal */
		return EINTR;
	/*
	 * The following remapped because their number is in the POSIX range
	 */
	case ERROR_ARENA_TRASHED:
		return EFAULT;
	case ERROR_INVALID_BLOCK:
		return EIO;
	case ERROR_BAD_ENVIRONMENT:
		return EFAULT;
	case ERROR_BAD_FORMAT:
		return EINVAL;
	case ERROR_INVALID_DATA:
		return EIO;
	case ERROR_CURRENT_DIRECTORY:
		return ENOFILE;
	case ERROR_BAD_UNIT:
	case ERROR_BAD_DEVICE:
	case ERROR_NOT_READY:		/* No disk "in" the letter drive */
		return ENODEV;
	case ERROR_BAD_COMMAND:
	case ERROR_CRC:
	case ERROR_BAD_LENGTH:
	case ERROR_SEEK:
	case ERROR_NOT_DOS_DISK:
	case ERROR_SECTOR_NOT_FOUND:
	case ERROR_GEN_FAILURE:
	case ERROR_WRONG_DISK:
	case ERROR_SHARING_BUFFER_EXCEEDED:
	case ERROR_DEVICE_REMOVED:
		return EIO;
	case ERROR_OUT_OF_PAPER:
		return ENOSPC;
	case ERROR_WRITE_FAULT:
	case ERROR_READ_FAULT:
	case ERROR_NOACCESS:		/* Invalid access to memory location */
		return EFAULT;
	case ERROR_HANDLE_EOF:
		return 0;			/* EOF must be treated as a read of 0 bytes */
	case ERROR_HANDLE_DISK_FULL:
		return ENOSPC;
	case ERROR_ENVVAR_NOT_FOUND:
		/* Got this error writing to a closed stdio fd, opened via pipe() */
		return EBADF;
	case ERROR_BAD_EXE_FORMAT:
		return ENOEXEC;
	case ERROR_NETNAME_DELETED:
		return EHOSTUNREACH;
	case ERROR_NO_TOKEN:
		return ESRCH;
	case 0:					/* Always indicates success */
		return 0;
	default:
		printf("Windows error code %lu (%s) not remapped to a POSIX one",
				err, strerror(err));
	}

	return err;
}

static DWORD __map_mmap_prot_page(const int prot) {
    DWORD protect;
    
    if (prot == PROT_NONE)
        return 0;
        
    if ((prot & PROT_EXEC) != 0)
        protect = ((prot & PROT_WRITE) != 0) ? 
                    PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
    else
        protect = ((prot & PROT_WRITE) != 0) ?
                    PAGE_READWRITE : PAGE_READONLY;
    
    return protect;
}

static DWORD __map_mmap_prot_file(const int prot) {
    DWORD desiredAccess = 0;
    
    if (prot == PROT_NONE)
        return desiredAccess;
        
    if ((prot & PROT_READ) != 0)
        desiredAccess |= FILE_MAP_READ;
    if ((prot & PROT_WRITE) != 0)
        desiredAccess |= FILE_MAP_WRITE;
    if ((prot & PROT_EXEC) != 0)
        desiredAccess |= FILE_MAP_EXECUTE;
    
    return desiredAccess;
}

void* __NT_DCL mmap(void *addr, size_t len, int prot, int flags, int fildes, off64_t off) {
    HANDLE fm, h = INVALID_HANDLE_VALUE;
    void *map = MAP_FAILED;

    const DWORD dwFileOffsetLow = off & 0xFFFFFFFFL;
    const DWORD dwFileOffsetHigh = off >> 32;
    const DWORD protect = __map_mmap_prot_page(prot);
    const DWORD desiredAccess = __map_mmap_prot_file(prot);

    const off64_t maxSize = off + len;

    const DWORD dwMaxSizeLow = maxSize & 0xFFFFFFFFL;
    const DWORD dwMaxSizeHigh = maxSize >> 32;

    if (len == 0 || prot == PROT_EXEC) {
        errno = EINVAL;
        return MAP_FAILED;
    }

    if ((flags & MAP_ANONYMOUS) == 0 &&
	    (h = (HANDLE)_get_osfhandle(fildes)) == INVALID_HANDLE_VALUE) {
        errno = EBADF;
        NT_DEBUG("failed with %d (%s)", errno, strerror(errno));
        return MAP_FAILED;
    }

    fm = CreateFileMappingA(h, NULL, protect, dwMaxSizeHigh, dwMaxSizeLow, NULL);
    if (!fm) {
		errno = __map_mman_error(GetLastError());
        NT_DEBUG("failed with %d (%s)", errno, strerror(errno));
        return MAP_FAILED;
    }
  
    if ((flags & MAP_FIXED) == 0)
        map = MapViewOfFile(fm, desiredAccess, dwFileOffsetHigh, dwFileOffsetLow, len);
    else
        map = MapViewOfFileEx(fm, desiredAccess, dwFileOffsetHigh, dwFileOffsetLow, len, addr);

    /* maybe dont close handle? */ 
    CloseHandle(fm);
  
    if (!map){
		errno = __map_mman_error(GetLastError());
        NT_DEBUG("failed with %d (%s)", errno, strerror(errno));
        return MAP_FAILED;
    }

    return map;
}

int __NT_DCL munmap(void *addr, size_t len) {
    (void)len;

    if (UnmapViewOfFile(addr))
        return 0;
        
    errno =  __map_mman_error(GetLastError());
    return -1;
}