fn main() {
    println!("cargo:rustc-link-lib=dylib=EndpointSecurity");
    println!("cargo:rustc-link-lib=dylib=bsm");
}
