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

// Minimum version of the TSS 2.0 libraries that this crate can use.
const MINIMUM_VERSION: &str = "2.3.3";

fn main() {
    if cfg!(not(feature = "docs")) {
        let tss2_esys = pkg_config::Config::new()
            .atleast_version(MINIMUM_VERSION)
            .probe("tss2-esys")
            .expect("Error with pkg-config finding tss2-esys.");
        let tss2_tctildr = pkg_config::Config::new()
            .atleast_version(MINIMUM_VERSION)
            .probe("tss2-tctildr")
            .expect("Error with pkg-config finding tss2-tctildr.");

        // These two pkg-config files should contain only one include/lib path.
        let tss2_esys_include_path = tss2_esys.include_paths[0]
            .clone()
            .into_os_string()
            .into_string()
            .expect("Error converting OsString to String.");
        let tss2_tctildr_include_path = tss2_tctildr.include_paths[0]
            .clone()
            .into_os_string()
            .into_string()
            .expect("Error converting OsString to String.");

        let bindings = bindgen::Builder::default()
            .clang_arg(format!("-I{}/tss2/", tss2_esys_include_path))
            .clang_arg(format!("-I{}/tss2/", tss2_tctildr_include_path))
            .rustfmt_bindings(true)
            .header(format!("{}/tss2/tss2_esys.h", tss2_esys_include_path))
            .header(format!("{}/tss2/tss2_tctildr.h", tss2_tctildr_include_path))
            .generate_comments(false)
            .derive_default(true)
            .generate()
            .expect("Unable to generate bindings to TSS2 ESYS APIs.");

        let out_path = PathBuf::from(
            env::var("OUT_DIR").expect("Error while getting the OUT_DIR environment variable."),
        );
        bindings
            .write_to_file(out_path.join("tss2_esys_bindings.rs"))
            .unwrap_or_else(|_| panic!("Couldn't write bindings to {:?}!", out_path));
    }
}
