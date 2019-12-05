// Copyright (c) 2019, Arm Limited, All Rights Reserved
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//          http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
use std::env;
use std::path::PathBuf;

fn main() {
    let bindings = bindgen::Builder::default()
        .clang_arg(String::from("-I/usr/local/include/tss2/"))
        .rustfmt_bindings(true)
        .header(String::from("/usr/local/include/tss2/tss2_esys.h"))
        .header(String::from("/usr/local/include/tss2/tss2_tctildr.h"))
        .generate_comments(false)
        .derive_default(true)
        .generate()
        .expect("Unable to generate bindings to TSS2 ESYS APIs.");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("tss2_esys_bindings.rs"))
        .expect(&format!("Couldn't write bindings to {:?}!", out_path));

    println!("cargo:rustc-link-lib=tss2-esys");
    println!("cargo:rustc-link-lib=tss2-tctildr");
}
