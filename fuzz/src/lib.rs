//! What the fuzz targets share: an embedded Python running ryjwt's Python package (`../python`)
//! on this build of its extension module, instrumented for the fuzzer and its address sanitizer;
//! and `harness.py`, whose checks drive ryjwt's public API with each input and say whether what it
//! did was right. A check that raises is a finding, as is a panic or a sanitizer error.

use std::sync::OnceLock;

use pyo3::prelude::*;
use pyo3::types::PyBytes;

// Linked for its `PyInit__ryjwt`.
use _ryjwt as _;

unsafe extern "C" {
    /// The extension module's init function (the `#[pymodule]` in ../src/lib.rs).
    fn PyInit__ryjwt() -> *mut pyo3::ffi::PyObject;
}

/// The target's check: harness.py's `check(target)`, a callable taking each input as bytes.
static CHECK: OnceLock<Py<PyAny>> = OnceLock::new();

/// Starts Python with this build of ryjwt's extension module as `ryjwt._ryjwt`, and loads the
/// check for `target`.
///
/// # Panics
///
/// If the environment isn't set up as `task fuzz` sets it up, or harness.py fails to load.
pub fn init(target: &str) {
    // Python's own allocator would hide its objects' buffers from AddressSanitizer.
    assert!(
        std::env::var("PYTHONMALLOC").as_deref() == Ok("malloc"),
        "Run the fuzz targets with `task fuzz`, which sets PYTHONMALLOC=malloc, PYTHONHOME and \
         PYTHONPATH"
    );
    // SAFETY: Python isn't initialised yet, as PyImport_AppendInittab requires, and the name is a
    // static C string, which outlives the interpreter as the inittab needs it to.
    let status =
        unsafe { pyo3::ffi::PyImport_AppendInittab(c"ryjwt._ryjwt".as_ptr(), Some(PyInit__ryjwt)) };
    assert_eq!(status, 0, "PyImport_AppendInittab failed");
    Python::initialize();
    let check = Python::attach(|py| {
        match py
            .import("harness")
            .and_then(|harness| harness.call_method1("check", (target,)))
        {
            Ok(check) => check.unbind(),
            Err(e) => {
                e.display(py);
                panic!("harness.py failed to load (traceback above)");
            }
        }
    });
    assert!(CHECK.set(check).is_ok(), "init ran twice");
}

/// Runs the check on `data`, panicking (which the fuzzer reports, with `data`) if it raises.
///
/// # Panics
///
/// If the check raises, or `init` hasn't run.
pub fn run(data: &[u8]) {
    Python::attach(|py| {
        let check = CHECK.get().expect("init runs first").bind(py);
        if let Err(e) = check.call1((PyBytes::new(py, data),)) {
            e.display(py);
            panic!("harness.py's check failed (traceback above)");
        }
    });
}
