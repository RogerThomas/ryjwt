//! Links the fuzz targets with an rpath to the libpython they embed (`PYO3_PYTHON`'s), so they run
//! without `LD_LIBRARY_PATH`.

fn main() {
    pyo3_build_config::add_libpython_rpath_link_args();
}
