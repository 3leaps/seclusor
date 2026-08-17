//! CLI-private hidden terminal input.
//!
//! The platform adapters disable echo with an RAII guard and restore the
//! original terminal mode on explicit return and during unwinding. Plaintext
//! bytes live in capped zeroizing buffers from their first userspace read.

use std::io;
#[cfg(test)]
use std::io::Read;

use zeroize::Zeroizing;

use crate::resolve::interactive_console_available;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HiddenInputError {
    Unavailable,
    Interrupted,
    Read,
    TooLong,
}

#[derive(Debug)]
enum BoundedLineOutcome {
    Value(Zeroizing<Vec<u8>>),
    TooLong,
}

fn write_prompt<W: io::Write>(writer: &mut W) -> io::Result<()> {
    write!(writer, "Value: ")?;
    writer.flush()
}

trait EchoControl {
    fn restore_echo(&mut self) -> io::Result<()>;
}

fn run_hidden_session<C, T>(
    console: &mut C,
    read: impl FnOnce(&mut C) -> io::Result<T>,
) -> io::Result<T>
where
    C: EchoControl,
{
    if let Err(err) = write_prompt(&mut std::io::stderr()) {
        let _ = console.restore_echo();
        return Err(err);
    }
    let read_result = read(console);
    let restore_result = console.restore_echo();
    eprintln!();
    match (read_result, restore_result) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(err), _) | (Ok(_), Err(err)) => Err(err),
    }
}

struct BoundedLine {
    bytes: Zeroizing<Vec<u8>>,
    limit: usize,
    overflowed: bool,
}

impl BoundedLine {
    fn new(limit: usize) -> Self {
        Self {
            // One extra byte permits an exact-limit value followed by the CR
            // half of a CRLF terminator without growing the allocation.
            bytes: Zeroizing::new(Vec::with_capacity(limit.saturating_add(1))),
            limit,
            overflowed: false,
        }
    }

    /// Feed bytes and return true after a line-feed terminator is consumed.
    ///
    /// Once the cap is reached, subsequent bytes are drained but never
    /// retained. LF is never stored; a preceding CR is stripped in `finish`.
    #[cfg(any(windows, test))]
    fn feed(&mut self, chunk: &[u8]) -> bool {
        for &byte in chunk {
            if byte == b'\n' {
                return true;
            }
            self.push(byte);
        }
        false
    }

    fn push(&mut self, byte: u8) {
        if self.bytes.len() < self.limit.saturating_add(1) {
            self.bytes.push(byte);
        } else {
            self.overflowed = true;
        }
    }

    fn erase_last(&mut self) {
        // Once unretained bytes have crossed the cap, the reader cannot
        // reconstruct the edited value without retaining them. Keep the
        // fail-closed overflow result instead.
        if !self.overflowed {
            while let Some(byte) = self.bytes.pop() {
                if byte & 0b1100_0000 != 0b1000_0000 {
                    break;
                }
            }
        }
    }

    fn finish(mut self, terminated: bool) -> BoundedLineOutcome {
        if terminated && self.bytes.ends_with(b"\r") {
            self.bytes.pop();
        }
        if self.overflowed || self.bytes.len() > self.limit {
            BoundedLineOutcome::TooLong
        } else {
            BoundedLineOutcome::Value(self.bytes)
        }
    }
}

#[cfg(test)]
fn read_bounded_line_bytes<R: Read>(
    reader: &mut R,
    limit: usize,
) -> io::Result<BoundedLineOutcome> {
    let mut line = BoundedLine::new(limit);
    let mut chunk = Zeroizing::new([0u8; 512]);
    loop {
        let read = reader.read(&mut *chunk)?;
        if read == 0 {
            return Ok(line.finish(false));
        }
        if line.feed(&chunk[..read]) {
            return Ok(line.finish(true));
        }
    }
}

/// Read one hidden line from the controlling console.
///
/// This function performs the existing controlling-console preflight before
/// printing the prompt and never falls back to stdin.
pub(crate) fn read_hidden_line_bounded(
    limit: usize,
) -> Result<Zeroizing<Vec<u8>>, HiddenInputError> {
    if !interactive_console_available() {
        return Err(HiddenInputError::Unavailable);
    }

    let outcome = platform::read_hidden_line(limit).map_err(|err| {
        if err.kind() == io::ErrorKind::Interrupted {
            HiddenInputError::Interrupted
        } else {
            HiddenInputError::Read
        }
    })?;
    match outcome {
        BoundedLineOutcome::Value(bytes) => Ok(bytes),
        BoundedLineOutcome::TooLong => Err(HiddenInputError::TooLong),
    }
}

#[cfg(unix)]
mod platform {
    use std::fs::{File, OpenOptions};
    use std::io::{self, Read};
    use std::mem::MaybeUninit;
    use std::os::fd::{AsRawFd, RawFd};

    use super::{run_hidden_session, BoundedLineOutcome, EchoControl};

    struct HiddenConsole {
        file: File,
        fd: RawFd,
        original: libc::termios,
        interrupt: libc::cc_t,
        erase: libc::cc_t,
        restored: bool,
    }

    impl HiddenConsole {
        fn open() -> io::Result<Self> {
            let file = OpenOptions::new().read(true).write(true).open("/dev/tty")?;
            Self::from_file(file)
        }

        fn from_file(file: File) -> io::Result<Self> {
            let fd = file.as_raw_fd();
            let mut original = MaybeUninit::<libc::termios>::uninit();
            // SAFETY: `fd` belongs to the live `File`, and `tcgetattr` writes a
            // complete termios value on success.
            if unsafe { libc::tcgetattr(fd, original.as_mut_ptr()) } != 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: the successful `tcgetattr` initialized `original`.
            let original = unsafe { original.assume_init() };
            let mut hidden = original;
            hidden.c_lflag &= !(libc::ECHO | libc::ECHONL | libc::ICANON | libc::ISIG);
            hidden.c_iflag &= !(libc::IGNCR | libc::INLCR);
            hidden.c_iflag |= libc::ICRNL;
            hidden.c_cc[libc::VMIN] = 1;
            hidden.c_cc[libc::VTIME] = 0;
            // SAFETY: both pointers reference initialized termios values and
            // `fd` remains open for the lifetime of the guard.
            if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &hidden) } != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self {
                file,
                fd,
                original,
                interrupt: original.c_cc[libc::VINTR],
                erase: original.c_cc[libc::VERASE],
                restored: false,
            })
        }
    }

    impl EchoControl for HiddenConsole {
        fn restore_echo(&mut self) -> io::Result<()> {
            if self.restored {
                return Ok(());
            }
            // SAFETY: `fd` is still owned by `file`, and `original` is the
            // terminal mode captured before echo was disabled.
            if unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.original) } != 0 {
                return Err(io::Error::last_os_error());
            }
            self.restored = true;
            Ok(())
        }
    }

    impl Drop for HiddenConsole {
        fn drop(&mut self) {
            let _ = self.restore_echo();
        }
    }

    pub(super) fn read_hidden_line(limit: usize) -> io::Result<BoundedLineOutcome> {
        let mut console = HiddenConsole::open()?;
        run_hidden_session(&mut console, |console| read_terminal_line(console, limit))
    }

    fn read_terminal_line(
        console: &mut HiddenConsole,
        limit: usize,
    ) -> io::Result<BoundedLineOutcome> {
        let mut line = super::BoundedLine::new(limit);
        let mut chunk = zeroize::Zeroizing::new([0u8; 512]);
        loop {
            let read = console.file.read(&mut *chunk)?;
            if read == 0 {
                return Ok(line.finish(false));
            }
            for &byte in &chunk[..read] {
                if byte == console.interrupt {
                    return Err(io::Error::from(io::ErrorKind::Interrupted));
                }
                if byte == console.erase {
                    line.erase_last();
                } else if byte == b'\r' || byte == b'\n' {
                    return Ok(line.finish(true));
                } else {
                    line.push(byte);
                }
            }
        }
    }

    #[cfg(test)]
    pub(super) fn read_hidden_line_from_file(
        file: File,
        limit: usize,
    ) -> io::Result<BoundedLineOutcome> {
        let mut console = HiddenConsole::from_file(file)?;
        run_hidden_session(&mut console, |console| read_terminal_line(console, limit))
    }
}

#[cfg(windows)]
mod platform {
    use std::fs::{File, OpenOptions};
    use std::io;
    use std::os::windows::io::AsRawHandle;
    use std::ptr;

    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::System::Console::{
        GetConsoleMode, ReadConsoleW, SetConsoleMode, CONSOLE_MODE, ENABLE_ECHO_INPUT,
        ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT,
    };
    use zeroize::Zeroizing;

    use super::{run_hidden_session, BoundedLine, BoundedLineOutcome, EchoControl};

    struct HiddenConsole {
        _file: File,
        handle: HANDLE,
        original: CONSOLE_MODE,
        restored: bool,
    }

    impl HiddenConsole {
        fn open() -> io::Result<Self> {
            let file = OpenOptions::new().read(true).write(true).open("CONIN$")?;
            let handle = file.as_raw_handle() as HANDLE;
            let mut original = 0;
            // SAFETY: `handle` is a live console handle and `original` points
            // to writable storage for the console mode.
            if unsafe { GetConsoleMode(handle, &mut original) } == 0 {
                return Err(io::Error::last_os_error());
            }
            let hidden = hidden_console_mode(original);
            // SAFETY: `handle` remains live and `hidden` is derived from its
            // current mode with only processed-input, line-input, and echo
            // bits changed.
            if unsafe { SetConsoleMode(handle, hidden) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self {
                _file: file,
                handle,
                original,
                restored: false,
            })
        }
    }

    impl EchoControl for HiddenConsole {
        fn restore_echo(&mut self) -> io::Result<()> {
            if self.restored {
                return Ok(());
            }
            // SAFETY: `handle` is owned by the still-live `file`; `original`
            // is the exact mode captured before echo was disabled.
            if unsafe { SetConsoleMode(self.handle, self.original) } == 0 {
                return Err(io::Error::last_os_error());
            }
            self.restored = true;
            Ok(())
        }
    }

    impl Drop for HiddenConsole {
        fn drop(&mut self) {
            let _ = self.restore_echo();
        }
    }

    fn feed_utf16(
        line: &mut BoundedLine,
        units: &[u16],
        pending_high: &mut Zeroizing<Vec<u16>>,
    ) -> io::Result<bool> {
        for &unit in units {
            if pending_high.is_empty() {
                if unit == 0x0003 {
                    return Err(io::Error::from(io::ErrorKind::Interrupted));
                }
                if unit == 0x0008 {
                    line.erase_last();
                    continue;
                }
                if unit == b'\r' as u16 || unit == b'\n' as u16 {
                    return Ok(true);
                }
            }
            let scalar = if let Some(high) = pending_high.pop() {
                if !(0xDC00..=0xDFFF).contains(&unit) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid console input",
                    ));
                }
                0x10000 + (((high as u32) - 0xD800) << 10) + ((unit as u32) - 0xDC00)
            } else if (0xD800..=0xDBFF).contains(&unit) {
                pending_high.push(unit);
                continue;
            } else if (0xDC00..=0xDFFF).contains(&unit) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid console input",
                ));
            } else {
                unit as u32
            };

            let ch = char::from_u32(scalar).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid console input")
            })?;
            let mut encoded = Zeroizing::new([0u8; 4]);
            let encoded_len = ch.encode_utf8(&mut *encoded).len();
            if line.feed(&encoded[..encoded_len]) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn hidden_console_mode(original: CONSOLE_MODE) -> CONSOLE_MODE {
        original & !(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT)
    }

    pub(super) fn read_hidden_line(limit: usize) -> io::Result<BoundedLineOutcome> {
        let mut console = HiddenConsole::open()?;
        run_hidden_session(&mut console, |console| {
            let mut line = BoundedLine::new(limit);
            let mut units = Zeroizing::new([0u16; 256]);
            let mut pending_high = Zeroizing::new(Vec::with_capacity(1));
            loop {
                let mut read = 0u32;
                // SAFETY: `handle` is a live console input handle; `units` is a
                // writable array of `u16`; `read` receives the initialized count.
                if unsafe {
                    ReadConsoleW(
                        console.handle,
                        units.as_mut_ptr().cast(),
                        units.len() as u32,
                        &mut read,
                        ptr::null(),
                    )
                } == 0
                {
                    break Err(io::Error::last_os_error());
                }
                if read == 0 {
                    if pending_high.is_empty() {
                        break Ok(line.finish(false));
                    }
                    break Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid console input",
                    ));
                }
                match feed_utf16(&mut line, &units[..read as usize], &mut pending_high) {
                    Ok(true) => break Ok(line.finish(true)),
                    Ok(false) => {}
                    Err(err) => break Err(err),
                }
            }
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn hidden_mode_disables_echo_line_and_processed_input() {
            let original = ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT | 0x0080;
            let hidden = hidden_console_mode(original);
            assert_eq!(
                hidden & (ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT),
                0
            );
            assert_eq!(hidden & 0x0080, 0x0080);
        }
    }
}

#[cfg(not(any(unix, windows)))]
mod platform {
    use std::io;

    use super::BoundedLineOutcome;

    pub(super) fn read_hidden_line(_limit: usize) -> io::Result<BoundedLineOutcome> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "interactive terminal input is unsupported",
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::io::{Cursor, Read};
    use std::rc::Rc;

    use super::*;

    #[test]
    fn bounded_line_accepts_empty_lf_and_strips_crlf() {
        let empty = read_bounded_line_bytes(&mut Cursor::new(b"\n"), 4).expect("read");
        assert!(matches!(empty, BoundedLineOutcome::Value(v) if v.is_empty()));

        let crlf = read_bounded_line_bytes(&mut Cursor::new(b"abcd\r\n"), 4).expect("read");
        assert!(matches!(crlf, BoundedLineOutcome::Value(v) if v.as_slice() == b"abcd"));
    }

    #[test]
    fn bounded_line_never_retains_beyond_cap_and_drains_overflow() {
        struct OneByteReader {
            inner: Cursor<Vec<u8>>,
            bytes_read: usize,
        }

        impl Read for OneByteReader {
            fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
                let limit = out.len().min(1);
                let read = self.inner.read(&mut out[..limit])?;
                self.bytes_read += read;
                Ok(read)
            }
        }

        let input = b"abcdef\nnext".to_vec();
        let mut reader = OneByteReader {
            inner: Cursor::new(input),
            bytes_read: 0,
        };
        let outcome = read_bounded_line_bytes(&mut reader, 4).expect("read");
        assert!(matches!(outcome, BoundedLineOutcome::TooLong));
        assert_eq!(reader.bytes_read, 7, "overflow line must be fully drained");
    }

    #[test]
    fn bounded_line_exact_limit_and_over_limit_are_distinct() {
        let exact = read_bounded_line_bytes(&mut Cursor::new(b"abcd\n"), 4).expect("read");
        assert!(matches!(exact, BoundedLineOutcome::Value(v) if v.as_slice() == b"abcd"));

        let over = read_bounded_line_bytes(&mut Cursor::new(b"abcde\n"), 4).expect("read");
        assert!(matches!(over, BoundedLineOutcome::TooLong));
    }

    #[test]
    fn terminal_erase_removes_one_utf8_scalar() {
        let mut line = BoundedLine::new(16);
        for byte in "a€".as_bytes() {
            line.push(*byte);
        }
        line.erase_last();
        assert!(matches!(
            line.finish(true),
            BoundedLineOutcome::Value(v) if v.as_slice() == b"a"
        ));
    }

    #[test]
    fn hidden_input_errors_are_content_free() {
        for err in [
            HiddenInputError::Unavailable,
            HiddenInputError::Interrupted,
            HiddenInputError::Read,
            HiddenInputError::TooLong,
        ] {
            let rendered = format!("{err:?}");
            assert!(!rendered.contains("plaintext"));
        }
    }

    #[test]
    fn console_mock_restores_echo_and_emits_prompt_only() {
        struct MockConsole {
            input: Cursor<Vec<u8>>,
            restored: Rc<Cell<bool>>,
        }

        impl Read for MockConsole {
            fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
                self.input.read(out)
            }
        }

        impl EchoControl for MockConsole {
            fn restore_echo(&mut self) -> io::Result<()> {
                self.restored.set(true);
                Ok(())
            }
        }

        let restored = Rc::new(Cell::new(false));
        let entered_value = b"console-mock-value";
        let mut console = MockConsole {
            input: Cursor::new([entered_value.as_slice(), b"\n"].concat()),
            restored: Rc::clone(&restored),
        };
        let outcome =
            run_hidden_session(&mut console, |console| read_bounded_line_bytes(console, 64))
                .expect("hidden session");
        assert!(matches!(
            outcome,
            BoundedLineOutcome::Value(v) if v.as_slice() == entered_value
        ));
        assert!(restored.get(), "echo must restore after success");

        let mut rendered_prompt = Vec::new();
        write_prompt(&mut rendered_prompt).expect("prompt");
        assert_eq!(rendered_prompt, b"Value: ");
        assert!(!rendered_prompt
            .windows(entered_value.len())
            .any(|window| window == entered_value));
    }

    #[test]
    fn console_mock_restores_echo_after_read_error() {
        struct ErrorConsole {
            restored: Rc<Cell<bool>>,
        }

        impl EchoControl for ErrorConsole {
            fn restore_echo(&mut self) -> io::Result<()> {
                self.restored.set(true);
                Ok(())
            }
        }

        let restored = Rc::new(Cell::new(false));
        let mut console = ErrorConsole {
            restored: Rc::clone(&restored),
        };
        let result: io::Result<()> = run_hidden_session(&mut console, |_| {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "read failed"))
        });
        assert!(result.is_err());
        assert!(restored.get(), "echo must restore after read error");
    }

    #[test]
    fn console_mock_restores_echo_during_unwind() {
        struct PanicConsole {
            restored: Rc<Cell<bool>>,
        }

        impl EchoControl for PanicConsole {
            fn restore_echo(&mut self) -> io::Result<()> {
                self.restored.set(true);
                Ok(())
            }
        }

        impl Drop for PanicConsole {
            fn drop(&mut self) {
                let _ = self.restore_echo();
            }
        }

        let restored = Rc::new(Cell::new(false));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe({
            let restored = Rc::clone(&restored);
            move || {
                let mut console = PanicConsole { restored };
                let _: io::Result<()> = run_hidden_session(&mut console, |_| panic!("test unwind"));
            }
        }));
        assert!(result.is_err());
        assert!(restored.get(), "drop must restore echo during unwind");
    }

    #[cfg(unix)]
    fn open_pty() -> (std::fs::File, std::fs::File) {
        use std::os::fd::FromRawFd;

        let mut master = -1;
        let mut slave = -1;
        // SAFETY: `openpty` initializes both descriptors on success. The
        // optional name, termios, and winsize pointers may be null.
        let rc = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc, 0, "openpty: {}", io::Error::last_os_error());
        // SAFETY: successful `openpty` returned new owned descriptors.
        let master = unsafe { std::fs::File::from_raw_fd(master) };
        // SAFETY: successful `openpty` returned new owned descriptors.
        let slave = unsafe { std::fs::File::from_raw_fd(slave) };
        (master, slave)
    }

    #[cfg(unix)]
    fn terminal_mode(file: &std::fs::File) -> libc::termios {
        use std::mem::MaybeUninit;
        use std::os::fd::AsRawFd;

        let mut mode = MaybeUninit::<libc::termios>::uninit();
        // SAFETY: `file` is a live PTY descriptor and `tcgetattr` initializes
        // `mode` on success.
        let rc = unsafe { libc::tcgetattr(file.as_raw_fd(), mode.as_mut_ptr()) };
        assert_eq!(rc, 0, "tcgetattr: {}", io::Error::last_os_error());
        // SAFETY: successful `tcgetattr` initialized the value.
        unsafe { mode.assume_init() }
    }

    #[cfg(unix)]
    fn assert_terminal_mode_eq(expected: &libc::termios, actual: &libc::termios) {
        assert_eq!(actual.c_iflag, expected.c_iflag);
        assert_eq!(actual.c_oflag, expected.c_oflag);
        assert_eq!(actual.c_cflag, expected.c_cflag);
        // BSD kernels set the read-only/status-like PENDIN bit when switching
        // back to canonical mode. All user-configurable mode bits must match.
        assert_eq!(
            actual.c_lflag & !libc::PENDIN,
            expected.c_lflag & !libc::PENDIN
        );
        assert_eq!(actual.c_cc, expected.c_cc);
    }

    #[cfg(unix)]
    fn wait_for_noncanonical_mode(file: &std::fs::File) {
        for _ in 0..10_000 {
            let mode = terminal_mode(file);
            if mode.c_lflag & (libc::ICANON | libc::ISIG | libc::ECHO) == 0 {
                return;
            }
            std::thread::yield_now();
        }
        panic!("PTY never entered hidden noncanonical mode");
    }

    #[cfg(unix)]
    #[test]
    fn unix_pty_detects_overflow_beyond_canonical_limit_and_restores_mode() {
        use std::io::Write;

        let (mut master, slave) = open_pty();
        let inspector = slave.try_clone().expect("clone slave");
        let probe = slave.try_clone().expect("clone mode probe");
        let original = terminal_mode(&inspector);
        let limit = crate::handlers::encrypted_write::MAX_SET_VALUE_BYTES;
        let writer = std::thread::spawn(move || {
            wait_for_noncanonical_mode(&probe);
            let chunk = [b'x'; 8192];
            let mut remaining = limit + chunk.len();
            while remaining > 0 {
                let count = remaining.min(chunk.len());
                master.write_all(&chunk[..count]).expect("write value");
                remaining -= count;
            }
            master.write_all(b"\n").expect("write terminator");
            master
        });

        let outcome =
            platform::read_hidden_line_from_file(slave, limit).expect("read hidden PTY line");
        let _master = writer.join().expect("writer");
        assert!(matches!(outcome, BoundedLineOutcome::TooLong));
        assert_terminal_mode_eq(&original, &terminal_mode(&inspector));
    }

    #[cfg(unix)]
    #[test]
    fn unix_pty_interrupt_restores_exact_original_mode() {
        use std::io::Write;

        let (mut master, slave) = open_pty();
        let inspector = slave.try_clone().expect("clone slave");
        let probe = slave.try_clone().expect("clone mode probe");
        let original = terminal_mode(&inspector);
        let interrupt = original.c_cc[libc::VINTR];
        let writer = std::thread::spawn(move || {
            wait_for_noncanonical_mode(&probe);
            master.write_all(&[interrupt]).expect("write interrupt");
            master
        });

        let err = platform::read_hidden_line_from_file(slave, 64)
            .expect_err("interrupt must stop hidden input");
        let _master = writer.join().expect("writer");
        assert_eq!(err.kind(), io::ErrorKind::Interrupted);
        assert_terminal_mode_eq(&original, &terminal_mode(&inspector));
    }
}
