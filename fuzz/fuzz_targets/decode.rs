#![no_main]

libfuzzer_sys::fuzz_target!(init: ryjwt_fuzz::init("decode"), |data: &[u8]| ryjwt_fuzz::run(data));
