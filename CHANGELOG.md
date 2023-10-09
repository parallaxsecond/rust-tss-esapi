# Changelog

## [tss-esapi-sys-0.5.0](https://github.com/parallaxsecond/rust-tss-esapi/tree/tss-esapi-sys-0.5.0) (2023-10-06)

[Full Changelog](https://github.com/parallaxsecond/rust-tss-esapi/compare/tss-esapi-7.3.0...tss-esapi-sys-0.5.0)

**Merged pull requests:**

- Update darwin bindings [\#452](https://github.com/parallaxsecond/rust-tss-esapi/pull/452) ([gowthamsk-arm](https://github.com/gowthamsk-arm))
- Bump bitfield and num-derive to 0.4.0 [\#449](https://github.com/parallaxsecond/rust-tss-esapi/pull/449) ([tgonzalezorlandoarm](https://github.com/tgonzalezorlandoarm))
- Bump env_logger to 0.10.0 [\#443](https://github.com/parallaxsecond/rust-tss-esapi/pull/443) ([tgonzalezorlandoarm](https://github.com/tgonzalezorlandoarm))
- Bump picky-asn1 and picky-asn1-x509 to 0.8.0 and 0.12.0 [\#441](https://github.com/parallaxsecond/rust-tss-esapi/pull/441) ([tgonzalezorlandoarm](https://github.com/tgonzalezorlandoarm))
- Update MSRV to 1.66.0 [\#444](https://github.com/parallaxsecond/rust-tss-esapi/pull/444) ([tgonzalezorlandoarm](https://github.com/tgonzalezorlandoarm))
- Bump bindgen and update bindings [\#439](https://github.com/parallaxsecond/rust-tss-esapi/pull/439) ([gowthamsk-arm](https://github.com/gowthamsk-arm))
- Fix spelling mistakes and add spellcheck exceptions [\#447](https://github.com/parallaxsecond/rust-tss-esapi/pull/447) ([tgonzalezorlandoarm](https://github.com/tgonzalezorlandoarm))
- Bump picky crates to match parsec [\#440](https://github.com/parallaxsecond/rust-tss-esapi/pull/440) ([tgonzalezorlandoarm](https://github.com/tgonzalezorlandoarm))

## [tss-esapi-7.3.0](https://github.com/parallaxsecond/rust-tss-esapi/tree/tss-esapi-7.3.0) (2023-09-28)

[Full Changelog](https://github.com/parallaxsecond/rust-tss-esapi/compare/tss-esapi-7.2.0...tss-esapi-7.3.0)

**Closed issues:**

- No 7.3.0 tag in git [\#435](https://github.com/parallaxsecond/rust-tss-esapi/issues/435)
-  error  sign function  in Transientkeycontext [\#404](https://github.com/parallaxsecond/rust-tss-esapi/issues/404)
- rust-tss-esapi is not buildable on Fedora-38 and Fedora-rawhide [\#400](https://github.com/parallaxsecond/rust-tss-esapi/issues/400)
- error in key\_handle  in rsa\_encrypt using tss-esapi [\#399](https://github.com/parallaxsecond/rust-tss-esapi/issues/399)
- Key sizes for RSA and curves for ECC are not configurable in ECC abstractions [\#397](https://github.com/parallaxsecond/rust-tss-esapi/issues/397)

**Merged pull requests:**

- Bump version to 7.3 [\#434](https://github.com/parallaxsecond/rust-tss-esapi/pull/434) ([ionut-arm](https://github.com/ionut-arm))
- Bump picky-crates [\#427](https://github.com/parallaxsecond/rust-tss-esapi/pull/427) ([ionut-arm](https://github.com/ionut-arm))

## [tss-esapi-7.2.0](https://github.com/parallaxsecond/rust-tss-esapi/tree/tss-esapi-7.2.0) (2023-02-07)
## [tss-esapi-sys-0.4.0](https://github.com/parallaxsecond/rust-tss-esapi/tree/tss-esapi-sys-0.4.0) (2023-02-07)

[Full Changelog](https://github.com/parallaxsecond/rust-tss-esapi/compare/tss-esapi-7.1.0...tss-esapi-7.2.0)

- Expanded the list of supported `tpm2-tss` versions to include v4. [#382](https://github.com/parallaxsecond/rust-tss-esapi/issues/382)
- Fixed a bug in handle management that hindered some use cases. [#383](https://github.com/parallaxsecond/rust-tss-esapi/issues/383)
- Updated the FFI bindings using v0.63 of bindgen. [#392](https://github.com/parallaxsecond/rust-tss-esapi/pull/392)

## [tss-esapi-7.1.0](https://github.com/parallaxsecond/rust-tss-esapi/tree/tss-esapi-7.1.0) (2022-05-25)

- Fixed a security vulnerability related to using nonces when opening auth sessions. For more details see #344 .

[Full Changelog](https://github.com/parallaxsecond/rust-tss-esapi/compare/tss-esapi-6.1.2...tss-esapi-7.1.0)

**Implemented enhancements:**

- Restructure NvOpenOptions [\#342](https://github.com/parallaxsecond/rust-tss-esapi/pull/342) ([ionut-arm](https://github.com/ionut-arm))
- Implement ref conversions from TKC to Context [\#336](https://github.com/parallaxsecond/rust-tss-esapi/pull/336) ([ionut-arm](https://github.com/ionut-arm))

**Fixed bugs:**

- Fix dangling pointer issue [\#344](https://github.com/parallaxsecond/rust-tss-esapi/pull/344) ([ionut-arm](https://github.com/ionut-arm))

**Merged pull requests:**

- Add support for converting Public to SubjectPublicKeyInfo [\#341](https://github.com/parallaxsecond/rust-tss-esapi/pull/341) ([THS-on](https://github.com/THS-on))
- Fixes potential memory leaks from the ffi types. [\#340](https://github.com/parallaxsecond/rust-tss-esapi/pull/340) ([Superhepper](https://github.com/Superhepper))
- nv: Read, Seek and Write trait implementations [\#324](https://github.com/parallaxsecond/rust-tss-esapi/pull/324) ([rshearman](https://github.com/rshearman))

## [tss-esapi-6.1.2](https://github.com/parallaxsecond/rust-tss-esapi/tree/tss-esapi-6.1.2) (2022-05-25)

- Fixed a security vulnerability related to using nonces when opening auth sessions. For more details see #344 .

[Full Changelog](https://github.com/parallaxsecond/rust-tss-esapi/compare/tss-esapi-7.0.1...tss-esapi-6.1.2)

**Closed issues:**

- Error during start\_auth\_session \(TCTI related error ?\) [\#337](https://github.com/parallaxsecond/rust-tss-esapi/issues/337)

## [tss-esapi-7.0.1](https://github.com/parallaxsecond/rust-tss-esapi/tree/tss-esapi-7.0.1) (2022-03-18)

[Full Changelog](https://github.com/parallaxsecond/rust-tss-esapi/compare/tss-esapi-7.0.0...tss-esapi-7.0.1)

**Implemented enhancements:**

- Adds more session attributes tests. [\#331](https://github.com/parallaxsecond/rust-tss-esapi/pull/331) ([Superhepper](https://github.com/Superhepper))
- Adds more pcr structure tests. [\#328](https://github.com/parallaxsecond/rust-tss-esapi/pull/328) ([Superhepper](https://github.com/Superhepper))

**Closed issues:**

- Steps to a stable 7.0.0 [\#290](https://github.com/parallaxsecond/rust-tss-esapi/issues/290)

**Merged pull requests:**

- Bump Fedora version for CI to Fedora 35 [\#333](https://github.com/parallaxsecond/rust-tss-esapi/pull/333) ([puiterwijk](https://github.com/puiterwijk))
- Remove RSA primality test [\#332](https://github.com/parallaxsecond/rust-tss-esapi/pull/332) ([puiterwijk](https://github.com/puiterwijk))
- Adds code coverage badge to the readme. [\#329](https://github.com/parallaxsecond/rust-tss-esapi/pull/329) ([Superhepper](https://github.com/Superhepper))
- Check for documentation link errors [\#327](https://github.com/parallaxsecond/rust-tss-esapi/pull/327) ([wiktor-k](https://github.com/wiktor-k))
- Adds MSRV ci check [\#319](https://github.com/parallaxsecond/rust-tss-esapi/pull/319) ([Superhepper](https://github.com/Superhepper))

## [tss-esapi-7.0.0](https://github.com/parallaxsecond/rust-tss-esapi/tree/tss-esapi-7.0.0) (2022-02-15)

[Full Changelog](https://github.com/parallaxsecond/rust-tss-esapi/compare/tss-esapi-7.0.0-beta.2...tss-esapi-7.0.0)

**Fixed bugs:**

- Fix broken link in docs [\#326](https://github.com/parallaxsecond/rust-tss-esapi/pull/326) ([ionut-arm](https://github.com/ionut-arm))

**Closed issues:**

- 7.0.0-beta.1: AK template can no longer be customised [\#322](https://github.com/parallaxsecond/rust-tss-esapi/issues/322)

**Merged pull requests:**

- Bump tss-esapi to 7.0.0 [\#325](https://github.com/parallaxsecond/rust-tss-esapi/pull/325) ([ionut-arm](https://github.com/ionut-arm))

## [tss-esapi-7.0.0-beta.2](https://github.com/parallaxsecond/rust-tss-esapi/tree/tss-esapi-7.0.0-beta.2) (2022-02-08)

[Full Changelog](https://github.com/parallaxsecond/rust-tss-esapi/compare/tss-esapi-7.0.0-beta.1...tss-esapi-7.0.0-beta.2)

**Fixed bugs:**

- Allow customizing AK public [\#323](https://github.com/parallaxsecond/rust-tss-esapi/pull/323) ([ionut-arm](https://github.com/ionut-arm))

**Closed issues:**

- rust-tss-esapi-7.0.0-beta.1 tag not pushed to git [\#321](https://github.com/parallaxsecond/rust-tss-esapi/issues/321)

## [tss-esapi-7.0.0-beta.1](https://github.com/parallaxsecond/rust-tss-esapi/tree/tss-esapi-7.0.0-beta.1) (2022-02-04)

[Full Changelog](https://github.com/parallaxsecond/rust-tss-esapi/compare/tss-esapi-sys-0.3.0...tss-esapi-7.0.0-beta.1)

## [tss-esapi-sys-0.3.0](https://github.com/parallaxsecond/rust-tss-esapi/tree/tss-esapi-sys-0.3.0) (2022-02-04)

[Full Changelog](https://github.com/parallaxsecond/rust-tss-esapi/compare/tss-esapi-7.0.0-alpha.1...tss-esapi-sys-0.3.0)

**Implemented enhancements:**

- To few items in PcrSlot compared with what PcrSelectSize can indicate. [\#311](https://github.com/parallaxsecond/rust-tss-esapi/issues/311)
- Implement native type for TPML\_TAGGED\_PCR\_PROPERTY in CapabilityData. [\#305](https://github.com/parallaxsecond/rust-tss-esapi/issues/305)
- Create native type for the TPM2\_CC constants. [\#296](https://github.com/parallaxsecond/rust-tss-esapi/issues/296)
- Add testing against tpm2-tss v3.0.0 [\#269](https://github.com/parallaxsecond/rust-tss-esapi/issues/269)
- Re-implement subtract functionality for PcrSelectionList [\#259](https://github.com/parallaxsecond/rust-tss-esapi/issues/259)
- Make context methods that has arguments with types that cannot be copied, take a reference instead [\#254](https://github.com/parallaxsecond/rust-tss-esapi/issues/254)
- Add builder methods and move NvPublic [\#316](https://github.com/parallaxsecond/rust-tss-esapi/pull/316) ([ionut-arm](https://github.com/ionut-arm))
- Replace type in CapabilityData::EccCurves [\#312](https://github.com/parallaxsecond/rust-tss-esapi/pull/312) ([ionut-arm](https://github.com/ionut-arm))
- Update API to take ownership where needed [\#307](https://github.com/parallaxsecond/rust-tss-esapi/pull/307) ([ionut-arm](https://github.com/ionut-arm))
- Sensitive buffers [\#306](https://github.com/parallaxsecond/rust-tss-esapi/pull/306) ([ionut-arm](https://github.com/ionut-arm))
- Implement PublicBuffer [\#302](https://github.com/parallaxsecond/rust-tss-esapi/pull/302) ([ionut-arm](https://github.com/ionut-arm))
- Add ActivateCredential support for TKC [\#284](https://github.com/parallaxsecond/rust-tss-esapi/pull/284) ([ionut-arm](https://github.com/ionut-arm))
- Improved return values of pcr\_read. [\#281](https://github.com/parallaxsecond/rust-tss-esapi/pull/281) ([Superhepper](https://github.com/Superhepper))
- Expand importing functionality in TransientKeyCtx [\#276](https://github.com/parallaxsecond/rust-tss-esapi/pull/276) ([ionut-arm](https://github.com/ionut-arm))
- Add version testing to CI [\#275](https://github.com/parallaxsecond/rust-tss-esapi/pull/275) ([ionut-arm](https://github.com/ionut-arm))
- Bump bindings version; add Darwin bindings [\#265](https://github.com/parallaxsecond/rust-tss-esapi/pull/265) ([ionut-arm](https://github.com/ionut-arm))

**Fixed bugs:**

- PcrSlot wont compile if TPM2\_PCR\_SELECT\_MAX != 4 [\#310](https://github.com/parallaxsecond/rust-tss-esapi/issues/310)
- Build failure for tss-esapi 6.1.0 with zeroize\_derive 1.2.0 [\#260](https://github.com/parallaxsecond/rust-tss-esapi/issues/260)
- Investigate if context methods are using incorrect types. [\#186](https://github.com/parallaxsecond/rust-tss-esapi/issues/186)
- Change default RSA exponent to 0 [\#292](https://github.com/parallaxsecond/rust-tss-esapi/pull/292) ([ionut-arm](https://github.com/ionut-arm))
- Change Name to TPM2B\_NAME conversion [\#288](https://github.com/parallaxsecond/rust-tss-esapi/pull/288) ([ionut-arm](https://github.com/ionut-arm))

**Closed issues:**

- Hierarchy/Unseal/Load auth value [\#309](https://github.com/parallaxsecond/rust-tss-esapi/issues/309)
- ActivateCredential error on non-6.1.1 versions \(Esys Finish ErrorCode \(0x00000101\)\) [\#285](https://github.com/parallaxsecond/rust-tss-esapi/issues/285)
- error while building [\#283](https://github.com/parallaxsecond/rust-tss-esapi/issues/283)
- doubts about TPMS\_ECC\_PARMS  [\#282](https://github.com/parallaxsecond/rust-tss-esapi/issues/282)
- Manually construct PcrData? [\#277](https://github.com/parallaxsecond/rust-tss-esapi/issues/277)
- Thank you [\#192](https://github.com/parallaxsecond/rust-tss-esapi/issues/192)
- Key management approach in abstraction::transient won't work in windows [\#169](https://github.com/parallaxsecond/rust-tss-esapi/issues/169)

**Merged pull requests:**

- Prepare 7.0.0-beta.1 release [\#320](https://github.com/parallaxsecond/rust-tss-esapi/pull/320) ([ionut-arm](https://github.com/ionut-arm))
- Updates depedencies [\#318](https://github.com/parallaxsecond/rust-tss-esapi/pull/318) ([Superhepper](https://github.com/Superhepper))
- Fixes some pcr issues. [\#317](https://github.com/parallaxsecond/rust-tss-esapi/pull/317) ([Superhepper](https://github.com/Superhepper))
- Creates native type for TPML\_CCA [\#315](https://github.com/parallaxsecond/rust-tss-esapi/pull/315) ([Superhepper](https://github.com/Superhepper))
- Make the crate compatible with 1.53 toolchain [\#314](https://github.com/parallaxsecond/rust-tss-esapi/pull/314) ([ionut-arm](https://github.com/ionut-arm))
- Rust native TPML\_TAGGED\_PCR\_PROPERTY type [\#308](https://github.com/parallaxsecond/rust-tss-esapi/pull/308) ([Superhepper](https://github.com/Superhepper))
- Updates CapabilityData to use AlgorithmPropertyList [\#304](https://github.com/parallaxsecond/rust-tss-esapi/pull/304) ([Superhepper](https://github.com/Superhepper))
- Fix typos and introduce Check spelling CI step [\#303](https://github.com/parallaxsecond/rust-tss-esapi/pull/303) ([wiktor-k](https://github.com/wiktor-k))
- Adds TaggedTpmProprtyList [\#301](https://github.com/parallaxsecond/rust-tss-esapi/pull/301) ([Superhepper](https://github.com/Superhepper))
- Command code list [\#300](https://github.com/parallaxsecond/rust-tss-esapi/pull/300) ([Superhepper](https://github.com/Superhepper))
- Adds CommandCode enum and replaces use of TPM2\_CC. [\#299](https://github.com/parallaxsecond/rust-tss-esapi/pull/299) ([Superhepper](https://github.com/Superhepper))
- Support Certify context command [\#297](https://github.com/parallaxsecond/rust-tss-esapi/pull/297) ([rshearman](https://github.com/rshearman))
- Removes TPMA\_LOCALITY from context methods. [\#294](https://github.com/parallaxsecond/rust-tss-esapi/pull/294) ([Superhepper](https://github.com/Superhepper))
- Adds the attest structures [\#293](https://github.com/parallaxsecond/rust-tss-esapi/pull/293) ([Superhepper](https://github.com/Superhepper))
- Suppress deref\_nullptr warnings [\#289](https://github.com/parallaxsecond/rust-tss-esapi/pull/289) ([ionut-arm](https://github.com/ionut-arm))
- Added SignatureScheme type. [\#286](https://github.com/parallaxsecond/rust-tss-esapi/pull/286) ([Superhepper](https://github.com/Superhepper))
- Make Name wrap the raw type directly [\#280](https://github.com/parallaxsecond/rust-tss-esapi/pull/280) ([wiktor-k](https://github.com/wiktor-k))
- Add `policy_duplication_select` to Context [\#278](https://github.com/parallaxsecond/rust-tss-esapi/pull/278) ([wiktor-k](https://github.com/wiktor-k))
- Added auth\_policy method to ther Public structure. [\#274](https://github.com/parallaxsecond/rust-tss-esapi/pull/274) ([Superhepper](https://github.com/Superhepper))
- Improved tests and naming for CapabilityType [\#273](https://github.com/parallaxsecond/rust-tss-esapi/pull/273) ([Superhepper](https://github.com/Superhepper))
- Fix a typo in "bitfield" [\#272](https://github.com/parallaxsecond/rust-tss-esapi/pull/272) ([wiktor-k](https://github.com/wiktor-k))
- Fix builders when using Null symmetric \(and a couple of small fixes\) [\#271](https://github.com/parallaxsecond/rust-tss-esapi/pull/271) ([wiktor-k](https://github.com/wiktor-k))
- Add a hint for unique\_identifier functions [\#270](https://github.com/parallaxsecond/rust-tss-esapi/pull/270) ([wiktor-k](https://github.com/wiktor-k))
- Fix error comment for ECC decryption keys [\#268](https://github.com/parallaxsecond/rust-tss-esapi/pull/268) ([wiktor-k](https://github.com/wiktor-k))
- Fix tss2\_esys version detection + new load\_external test [\#267](https://github.com/parallaxsecond/rust-tss-esapi/pull/267) ([rshearman](https://github.com/rshearman))
- Add TPM Import command [\#266](https://github.com/parallaxsecond/rust-tss-esapi/pull/266) ([wiktor-k](https://github.com/wiktor-k))
- Add property tag variant for MaxCapBuffer [\#264](https://github.com/parallaxsecond/rust-tss-esapi/pull/264) ([rshearman](https://github.com/rshearman))
- Fix abstraction nv handle leaks [\#263](https://github.com/parallaxsecond/rust-tss-esapi/pull/263) ([rshearman](https://github.com/rshearman))
- Refactoring and improvement of tests [\#258](https://github.com/parallaxsecond/rust-tss-esapi/pull/258) ([Superhepper](https://github.com/Superhepper))
- Add duplication command [\#248](https://github.com/parallaxsecond/rust-tss-esapi/pull/248) ([wiktor-k](https://github.com/wiktor-k))

## [tss-esapi-7.0.0-alpha.1](https://github.com/parallaxsecond/rust-tss-esapi/tree/tss-esapi-7.0.0-alpha.1) (2021-09-17)

[Full Changelog](https://github.com/parallaxsecond/rust-tss-esapi/compare/tss-esapi-6.1.0...tss-esapi-7.0.0-alpha.1)

**Implemented enhancements:**

- Missing check for key handle session where they are required [\#252](https://github.com/parallaxsecond/rust-tss-esapi/issues/252)
- Move TransientKeyContext away from contexts [\#256](https://github.com/parallaxsecond/rust-tss-esapi/pull/256) ([ionut-arm](https://github.com/ionut-arm))

**Fixed bugs:**

- The Context Management Tests are not executed [\#250](https://github.com/parallaxsecond/rust-tss-esapi/issues/250)

**Closed issues:**

- Getting the u32 value of a TpmHandle. [\#231](https://github.com/parallaxsecond/rust-tss-esapi/issues/231)
- Problems with sessions in tests [\#200](https://github.com/parallaxsecond/rust-tss-esapi/issues/200)

**Merged pull requests:**

- Bump version for new alpha release [\#257](https://github.com/parallaxsecond/rust-tss-esapi/pull/257) ([ionut-arm](https://github.com/ionut-arm))
- Add ECDH-related functions [\#255](https://github.com/parallaxsecond/rust-tss-esapi/pull/255) ([wiktor-k](https://github.com/wiktor-k))
- Add missing key handle session checks [\#253](https://github.com/parallaxsecond/rust-tss-esapi/pull/253) ([Superhepper](https://github.com/Superhepper))
- Fixed issue with missing tests. [\#251](https://github.com/parallaxsecond/rust-tss-esapi/pull/251) ([Superhepper](https://github.com/Superhepper))
- Fix a typo in "persistent" [\#249](https://github.com/parallaxsecond/rust-tss-esapi/pull/249) ([wiktor-k](https://github.com/wiktor-k))
- Implemented conversion traits for PcrSlot. [\#247](https://github.com/parallaxsecond/rust-tss-esapi/pull/247) ([Superhepper](https://github.com/Superhepper))
- Update CHANGELOG.md [\#245](https://github.com/parallaxsecond/rust-tss-esapi/pull/245) ([ionut-arm](https://github.com/ionut-arm))
- Creates native rust type for TPM2B\_PUBLIC. [\#241](https://github.com/parallaxsecond/rust-tss-esapi/pull/241) ([Superhepper](https://github.com/Superhepper))

## [tss-esapi-6.1.0](https://github.com/parallaxsecond/rust-tss-esapi/tree/tss-esapi-6.1.0) (2021-08-04)

[Full Changelog](https://github.com/parallaxsecond/rust-tss-esapi/compare/tss-esapi-6.0.0...tss-esapi-6.1.0)

**Implemented enhancements:**

- Implement Send/Sync on TctiContext [\#246](https://github.com/parallaxsecond/rust-tss-esapi/pull/246) ([ionut-arm](https://github.com/ionut-arm))

## [tss-esapi-6.0.0](https://github.com/parallaxsecond/rust-tss-esapi/tree/tss-esapi-6.0.0) (2021-08-04)

[Full Changelog](https://github.com/parallaxsecond/rust-tss-esapi/compare/tss-esapi-5.1.0...tss-esapi-6.0.0)

**Fixed bugs:**

- Fix some new clippy lints [\#242](https://github.com/parallaxsecond/rust-tss-esapi/pull/242) ([hug-dev](https://github.com/hug-dev))
- Fix tests [\#230](https://github.com/parallaxsecond/rust-tss-esapi/pull/230) ([ionut-arm](https://github.com/ionut-arm))
- Add tss2-sys when generating bindings too [\#227](https://github.com/parallaxsecond/rust-tss-esapi/pull/227) ([ionut-arm](https://github.com/ionut-arm))
- Replace links with absolute paths [\#225](https://github.com/parallaxsecond/rust-tss-esapi/pull/225) ([hug-dev](https://github.com/hug-dev))
- Fixes [\#218](https://github.com/parallaxsecond/rust-tss-esapi/pull/218) ([ionut-arm](https://github.com/ionut-arm))
- Fix a failing bindgen test [\#215](https://github.com/parallaxsecond/rust-tss-esapi/pull/215) ([hug-dev](https://github.com/hug-dev))

**Closed issues:**

- Use the new TctiContext in the TSS Context [\#235](https://github.com/parallaxsecond/rust-tss-esapi/issues/235)
- How to call `Context::new` safely? [\#229](https://github.com/parallaxsecond/rust-tss-esapi/issues/229)

**Merged pull requests:**

- Bump version numbers for release [\#244](https://github.com/parallaxsecond/rust-tss-esapi/pull/244) ([ionut-arm](https://github.com/ionut-arm))
- Ensure PcrSelectionList retains order, \#2 [\#243](https://github.com/parallaxsecond/rust-tss-esapi/pull/243) ([ionut-arm](https://github.com/ionut-arm))
- Remove old Tcti feature [\#239](https://github.com/parallaxsecond/rust-tss-esapi/pull/239) ([hug-dev](https://github.com/hug-dev))
- Ensure PcrData retains order [\#238](https://github.com/parallaxsecond/rust-tss-esapi/pull/238) ([puiterwijk](https://github.com/puiterwijk))
- Abstract execute\_With\_nullauth\_session return type [\#237](https://github.com/parallaxsecond/rust-tss-esapi/pull/237) ([puiterwijk](https://github.com/puiterwijk))
- Add a wrapper above the TCTI Loader library [\#234](https://github.com/parallaxsecond/rust-tss-esapi/pull/234) ([hug-dev](https://github.com/hug-dev))
- Update CHANGELOG for 5.1.0 [\#233](https://github.com/parallaxsecond/rust-tss-esapi/pull/233) ([ionut-arm](https://github.com/ionut-arm))
- Link to tss2-sys as well [\#226](https://github.com/parallaxsecond/rust-tss-esapi/pull/226) ([ionut-arm](https://github.com/ionut-arm))
- Adds the encrypt\_decrypt\_2 context method [\#220](https://github.com/parallaxsecond/rust-tss-esapi/pull/220) ([Superhepper](https://github.com/Superhepper))
- Modify handling of cross-compilation targets [\#219](https://github.com/parallaxsecond/rust-tss-esapi/pull/219) ([hug-dev](https://github.com/hug-dev))
- Bump bindgen to 0.57.0 [\#217](https://github.com/parallaxsecond/rust-tss-esapi/pull/217) ([eclipseo](https://github.com/eclipseo))
- Allow upper case acronyms [\#216](https://github.com/parallaxsecond/rust-tss-esapi/pull/216) ([ionut-arm](https://github.com/ionut-arm))
- Update CHANGELOG with new release [\#214](https://github.com/parallaxsecond/rust-tss-esapi/pull/214) ([hug-dev](https://github.com/hug-dev))


## [tss-esapi-5.1.0](https://github.com/parallaxsecond/rust-tss-esapi/tree/tss-esapi-5.1.0) (2021-06-17)

[Full Changelog](https://github.com/parallaxsecond/rust-tss-esapi/compare/tss-esapi-sys-0.2.0...tss-esapi-5.1.0)

## [tss-esapi-sys-0.2.0](https://github.com/parallaxsecond/rust-tss-esapi/tree/tss-esapi-sys-0.2.0) (2021-06-17)

[Full Changelog](https://github.com/parallaxsecond/rust-tss-esapi/compare/tss-esapi-5.0.1...tss-esapi-sys-0.2.0)

**Implemented enhancements:**

- Create generic list structure [\#92](https://github.com/parallaxsecond/rust-tss-esapi/issues/92)
- Bring Context method names closer to the TSS API [\#58](https://github.com/parallaxsecond/rust-tss-esapi/issues/58)
- Create and deploy enums for algorithm types [\#23](https://github.com/parallaxsecond/rust-tss-esapi/issues/23)
- Improve method signatures [\#6](https://github.com/parallaxsecond/rust-tss-esapi/issues/6)

**Closed issues:**

- Publish a stable version [\#148](https://github.com/parallaxsecond/rust-tss-esapi/issues/148)
## [tss-esapi-5.0.1](https://github.com/parallaxsecond/rust-tss-esapi/tree/tss-esapi-5.0.1) (2021-03-25)

[Full Changelog](https://github.com/parallaxsecond/rust-tss-esapi/compare/tss-esapi-sys-0.1.1...tss-esapi-5.0.1)

## [tss-esapi-sys-0.1.1](https://github.com/parallaxsecond/rust-tss-esapi/tree/tss-esapi-sys-0.1.1) (2021-03-25)

[Full Changelog](https://github.com/parallaxsecond/rust-tss-esapi/compare/tss-esapi-5.0.0...tss-esapi-sys-0.1.1)

**Fixed bugs:**

- Documentation fails building on docs.rs [\#211](https://github.com/parallaxsecond/rust-tss-esapi/issues/211)
- Fix cross-compilation scripts [\#212](https://github.com/parallaxsecond/rust-tss-esapi/pull/212) ([ionut-arm](https://github.com/ionut-arm))

**Merged pull requests:**

- Prepare patch release to fix docs.rs build [\#213](https://github.com/parallaxsecond/rust-tss-esapi/pull/213) ([hug-dev](https://github.com/hug-dev))
- Add a CHANGELOG file [\#210](https://github.com/parallaxsecond/rust-tss-esapi/pull/210) ([hug-dev](https://github.com/hug-dev))

## [tss-esapi-5.0.0](https://github.com/parallaxsecond/rust-tss-esapi/tree/tss-esapi-5.0.0) (2021-03-23)

[Full Changelog](https://github.com/parallaxsecond/rust-tss-esapi/compare/tss-esapi-sys-0.1.0...tss-esapi-5.0.0)

## [tss-esapi-sys-0.1.0](https://github.com/parallaxsecond/rust-tss-esapi/tree/tss-esapi-sys-0.1.0) (2021-03-23)

[Full Changelog](https://github.com/parallaxsecond/rust-tss-esapi/compare/4.0.10-alpha.2...tss-esapi-sys-0.1.0)

**Implemented enhancements:**

- Support and test cross-compilation [\#204](https://github.com/parallaxsecond/rust-tss-esapi/issues/204)
- Commit the ESAPI bindings if the ABI is stable [\#85](https://github.com/parallaxsecond/rust-tss-esapi/issues/85)
- Split in tss-esapi and tss-esapi-sys [\#30](https://github.com/parallaxsecond/rust-tss-esapi/issues/30)
- Allow changing the public exponent for RSA keys [\#13](https://github.com/parallaxsecond/rust-tss-esapi/issues/13)
- Add cross-compilation example to nightly [\#206](https://github.com/parallaxsecond/rust-tss-esapi/pull/206) ([ionut-arm](https://github.com/ionut-arm))
- This is an attempt to fix tests that fails locally. [\#201](https://github.com/parallaxsecond/rust-tss-esapi/pull/201) ([Superhepper](https://github.com/Superhepper))
- Add code coverage reporting [\#196](https://github.com/parallaxsecond/rust-tss-esapi/pull/196) ([ionut-arm](https://github.com/ionut-arm))
- Changed Session into an interface type. [\#195](https://github.com/parallaxsecond/rust-tss-esapi/pull/195) ([Superhepper](https://github.com/Superhepper))
- Interface types improvement [\#190](https://github.com/parallaxsecond/rust-tss-esapi/pull/190) ([Superhepper](https://github.com/Superhepper))
- Added the policy\_template context method. [\#189](https://github.com/parallaxsecond/rust-tss-esapi/pull/189) ([Superhepper](https://github.com/Superhepper))
- Refactored context integration tests. [\#188](https://github.com/parallaxsecond/rust-tss-esapi/pull/188) ([Superhepper](https://github.com/Superhepper))
- Split repo into two crates [\#177](https://github.com/parallaxsecond/rust-tss-esapi/pull/177) ([ionut-arm](https://github.com/ionut-arm))

**Fixed bugs:**

- nv\_define\_space and nv\_undefine\_space is using the wrong interface type. [\#184](https://github.com/parallaxsecond/rust-tss-esapi/issues/184)
- Fix cross-compile permissions [\#209](https://github.com/parallaxsecond/rust-tss-esapi/pull/209) ([ionut-arm](https://github.com/ionut-arm))
- Update registry for Dockerfiles [\#205](https://github.com/parallaxsecond/rust-tss-esapi/pull/205) ([ionut-arm](https://github.com/ionut-arm))
- Make codecov recognize environment [\#203](https://github.com/parallaxsecond/rust-tss-esapi/pull/203) ([ionut-arm](https://github.com/ionut-arm))

**Security fixes:**

- Log the commands sent and received to/from the TPM [\#86](https://github.com/parallaxsecond/rust-tss-esapi/issues/86)

**Merged pull requests:**

- Prepare the new crates versions [\#208](https://github.com/parallaxsecond/rust-tss-esapi/pull/208) ([hug-dev](https://github.com/hug-dev))
- CI: Fix all-fedora swtpm\_setup call [\#202](https://github.com/parallaxsecond/rust-tss-esapi/pull/202) ([puiterwijk](https://github.com/puiterwijk))
- ak, ek: allows use to pass options to key creation [\#199](https://github.com/parallaxsecond/rust-tss-esapi/pull/199) ([baloo](https://github.com/baloo))
- fixup rustfmt [\#194](https://github.com/parallaxsecond/rust-tss-esapi/pull/194) ([baloo](https://github.com/baloo))
- Enable running of hmac doctest [\#191](https://github.com/parallaxsecond/rust-tss-esapi/pull/191) ([puiterwijk](https://github.com/puiterwijk))
- Fixed interface types used for nv context methods. [\#185](https://github.com/parallaxsecond/rust-tss-esapi/pull/185) ([Superhepper](https://github.com/Superhepper))
- Moved ESAPI methods into their own files [\#183](https://github.com/parallaxsecond/rust-tss-esapi/pull/183) ([Superhepper](https://github.com/Superhepper))
- Changed location for attributes and some constants [\#182](https://github.com/parallaxsecond/rust-tss-esapi/pull/182) ([Superhepper](https://github.com/Superhepper))
- Added examples and improved documentation of evict control [\#181](https://github.com/parallaxsecond/rust-tss-esapi/pull/181) ([Superhepper](https://github.com/Superhepper))
- Make doc tests run and use env TCTI [\#180](https://github.com/parallaxsecond/rust-tss-esapi/pull/180) ([puiterwijk](https://github.com/puiterwijk))
- Split the Context into files per the TPM spec categorization [\#179](https://github.com/parallaxsecond/rust-tss-esapi/pull/179) ([puiterwijk](https://github.com/puiterwijk))
- Implement various TPM functions [\#178](https://github.com/parallaxsecond/rust-tss-esapi/pull/178) ([puiterwijk](https://github.com/puiterwijk))
- Fixed specifying size twice. [\#176](https://github.com/parallaxsecond/rust-tss-esapi/pull/176) ([Superhepper](https://github.com/Superhepper))
- Added NvIndexAttributesBuilder. [\#175](https://github.com/parallaxsecond/rust-tss-esapi/pull/175) ([Superhepper](https://github.com/Superhepper))
- Added proper documentation for pcr\_\* methods. [\#174](https://github.com/parallaxsecond/rust-tss-esapi/pull/174) ([Superhepper](https://github.com/Superhepper))
- Fixed lint errors from clippy [\#173](https://github.com/parallaxsecond/rust-tss-esapi/pull/173) ([Superhepper](https://github.com/Superhepper))
- Added missing size check when converting native buffer into TSS buffer. [\#171](https://github.com/parallaxsecond/rust-tss-esapi/pull/171) ([Superhepper](https://github.com/Superhepper))
- Improved session attributes [\#170](https://github.com/parallaxsecond/rust-tss-esapi/pull/170) ([Superhepper](https://github.com/Superhepper))

## [4.0.10-alpha.2](https://github.com/parallaxsecond/rust-tss-esapi/tree/4.0.10-alpha.2) (2020-12-17)

[Full Changelog](https://github.com/parallaxsecond/rust-tss-esapi/compare/4.0.10-alpha.1...4.0.10-alpha.2)

**Implemented enhancements:**

- Improve logging [\#157](https://github.com/parallaxsecond/rust-tss-esapi/pull/157) ([ionut-arm](https://github.com/ionut-arm))

**Fixed bugs:**

- Persistent objects should not be flushed from context [\#152](https://github.com/parallaxsecond/rust-tss-esapi/issues/152)
- Set session params only when it makes sense [\#156](https://github.com/parallaxsecond/rust-tss-esapi/pull/156) ([ionut-arm](https://github.com/ionut-arm))

**Merged pull requests:**

- Added documentation to Context methods. [\#168](https://github.com/parallaxsecond/rust-tss-esapi/pull/168) ([Superhepper](https://github.com/Superhepper))
- Bump alpha number [\#167](https://github.com/parallaxsecond/rust-tss-esapi/pull/167) ([ionut-arm](https://github.com/ionut-arm))
- Implement abstraction::ak [\#166](https://github.com/parallaxsecond/rust-tss-esapi/pull/166) ([puiterwijk](https://github.com/puiterwijk))
- Implement tpm2\_clear{,\_control} [\#165](https://github.com/parallaxsecond/rust-tss-esapi/pull/165) ([puiterwijk](https://github.com/puiterwijk))
- Make PCR Selection optional for create\_{primary\_,}key [\#164](https://github.com/parallaxsecond/rust-tss-esapi/pull/164) ([puiterwijk](https://github.com/puiterwijk))
- Implement changeauth operations [\#162](https://github.com/parallaxsecond/rust-tss-esapi/pull/162) ([puiterwijk](https://github.com/puiterwijk))
- Add policy\_{secret,signed} [\#161](https://github.com/parallaxsecond/rust-tss-esapi/pull/161) ([puiterwijk](https://github.com/puiterwijk))
- Update bindgen [\#159](https://github.com/parallaxsecond/rust-tss-esapi/pull/159) ([ionut-arm](https://github.com/ionut-arm))
- Add MakeCredential and ActivateCredential to Context [\#158](https://github.com/parallaxsecond/rust-tss-esapi/pull/158) ([puiterwijk](https://github.com/puiterwijk))
- Improved handling of handles on drop. [\#155](https://github.com/parallaxsecond/rust-tss-esapi/pull/155) ([Superhepper](https://github.com/Superhepper))
- Added support for tpm2-tss 3 [\#145](https://github.com/parallaxsecond/rust-tss-esapi/pull/145) ([Superhepper](https://github.com/Superhepper))
- Add startup method wrapper [\#133](https://github.com/parallaxsecond/rust-tss-esapi/pull/133) ([puiterwijk](https://github.com/puiterwijk))

## [4.0.10-alpha.1](https://github.com/parallaxsecond/rust-tss-esapi/tree/4.0.10-alpha.1) (2020-11-24)

[Full Changelog](https://github.com/parallaxsecond/rust-tss-esapi/compare/4.0.9-alpha.1...4.0.10-alpha.1)

**Implemented enhancements:**

- Add evict\_control API to context [\#135](https://github.com/parallaxsecond/rust-tss-esapi/issues/135)
- Depoly Session [\#126](https://github.com/parallaxsecond/rust-tss-esapi/issues/126)
- No private key analog to `load\_external\_rsa\_public\_key` [\#123](https://github.com/parallaxsecond/rust-tss-esapi/issues/123)
- Have two builds with two different TSS lib versions in CI [\#110](https://github.com/parallaxsecond/rust-tss-esapi/issues/110)
- Split between tss-esapi and tss-esapi-sys [\#75](https://github.com/parallaxsecond/rust-tss-esapi/issues/75)
- Create auth value wrapper [\#37](https://github.com/parallaxsecond/rust-tss-esapi/issues/37)
- Add method to use custom TCTI during test [\#132](https://github.com/parallaxsecond/rust-tss-esapi/pull/132) ([puiterwijk](https://github.com/puiterwijk))

**Fixed bugs:**

- Fix test compilation [\#149](https://github.com/parallaxsecond/rust-tss-esapi/pull/149) ([ionut-arm](https://github.com/ionut-arm))

**Security fixes:**

- Add zeroing to SensitiveData [\#128](https://github.com/parallaxsecond/rust-tss-esapi/pull/128) ([hug-dev](https://github.com/hug-dev))

**Merged pull requests:**

- Bump version to 4.0.10-alpha.1 [\#153](https://github.com/parallaxsecond/rust-tss-esapi/pull/153) ([ionut-arm](https://github.com/ionut-arm))
- Return all creation data [\#151](https://github.com/parallaxsecond/rust-tss-esapi/pull/151) ([puiterwijk](https://github.com/puiterwijk))
- Implement abstraction::nv::list [\#150](https://github.com/parallaxsecond/rust-tss-esapi/pull/150) ([puiterwijk](https://github.com/puiterwijk))
- Move Context functions to existing abstracted types [\#147](https://github.com/parallaxsecond/rust-tss-esapi/pull/147) ([puiterwijk](https://github.com/puiterwijk))
- Added evict\_control context method [\#146](https://github.com/parallaxsecond/rust-tss-esapi/pull/146) ([Superhepper](https://github.com/Superhepper))
- Add Fedora to CI [\#144](https://github.com/parallaxsecond/rust-tss-esapi/pull/144) ([puiterwijk](https://github.com/puiterwijk))
- Move create\_ctx\_with{,out}\_session from tests to common module [\#143](https://github.com/parallaxsecond/rust-tss-esapi/pull/143) ([puiterwijk](https://github.com/puiterwijk))
- Add support for SWTPM network TPM [\#142](https://github.com/parallaxsecond/rust-tss-esapi/pull/142) ([puiterwijk](https://github.com/puiterwijk))
- Implement utils::get\_tpm\_vendor [\#141](https://github.com/parallaxsecond/rust-tss-esapi/pull/141) ([puiterwijk](https://github.com/puiterwijk))
- Add CapabilityData abstraction for returned capability data [\#140](https://github.com/parallaxsecond/rust-tss-esapi/pull/140) ([puiterwijk](https://github.com/puiterwijk))
- Add abstraction::ek module [\#139](https://github.com/parallaxsecond/rust-tss-esapi/pull/139) ([puiterwijk](https://github.com/puiterwijk))
- Add abstraction::nv::read\_full to fully read an NV Index [\#138](https://github.com/parallaxsecond/rust-tss-esapi/pull/138) ([puiterwijk](https://github.com/puiterwijk))
- Add interface types [\#137](https://github.com/parallaxsecond/rust-tss-esapi/pull/137) ([Superhepper](https://github.com/Superhepper))
- Add Context.execute\_with\_session\(s\) functions [\#136](https://github.com/parallaxsecond/rust-tss-esapi/pull/136) ([puiterwijk](https://github.com/puiterwijk))
- Implement pcr\_{reset, extend} function wrappers [\#131](https://github.com/parallaxsecond/rust-tss-esapi/pull/131) ([puiterwijk](https://github.com/puiterwijk))
- Deployed Session and Handles in all places where they made sense. [\#129](https://github.com/parallaxsecond/rust-tss-esapi/pull/129) ([Superhepper](https://github.com/Superhepper))

## [4.0.9-alpha.1](https://github.com/parallaxsecond/rust-tss-esapi/tree/4.0.9-alpha.1) (2020-09-07)

[Full Changelog](https://github.com/parallaxsecond/rust-tss-esapi/compare/4.0.8-alpha.1...4.0.9-alpha.1)

**Implemented enhancements:**

- Create a session object. [\#66](https://github.com/parallaxsecond/rust-tss-esapi/issues/66)
- Create enum wrappers around resource handle types [\#24](https://github.com/parallaxsecond/rust-tss-esapi/issues/24)
- Upgrade dependencies [\#127](https://github.com/parallaxsecond/rust-tss-esapi/pull/127) ([hug-dev](https://github.com/hug-dev))
- Add `load\_external\_rsa\_keypair` function [\#124](https://github.com/parallaxsecond/rust-tss-esapi/pull/124) ([joechrisellis](https://github.com/joechrisellis))

**Fixed bugs:**

- NV contexts methods takes incorrect authorization argument. [\#113](https://github.com/parallaxsecond/rust-tss-esapi/issues/113)
- Implement secure data management [\#46](https://github.com/parallaxsecond/rust-tss-esapi/issues/46)

**Merged pull requests:**

- This commit deploys the new handle types and adds Session objects. [\#120](https://github.com/parallaxsecond/rust-tss-esapi/pull/120) ([Superhepper](https://github.com/Superhepper))

## [4.0.8-alpha.1](https://github.com/parallaxsecond/rust-tss-esapi/tree/4.0.8-alpha.1) (2020-08-13)

[Full Changelog](https://github.com/parallaxsecond/rust-tss-esapi/compare/4.0.7-alpha.1...4.0.8-alpha.1)

**Implemented enhancements:**

- Make several improvements [\#115](https://github.com/parallaxsecond/rust-tss-esapi/pull/115) ([ionut-arm](https://github.com/ionut-arm))

**Merged pull requests:**

- Bump version to 4.0.8-alpha.1 [\#117](https://github.com/parallaxsecond/rust-tss-esapi/pull/117) ([ionut-arm](https://github.com/ionut-arm))

## [4.0.7-alpha.1](https://github.com/parallaxsecond/rust-tss-esapi/tree/4.0.7-alpha.1) (2020-08-13)

[Full Changelog](https://github.com/parallaxsecond/rust-tss-esapi/compare/4.0.6-alpha.1...4.0.7-alpha.1)

**Implemented enhancements:**

- Add support for non volatile storage api [\#102](https://github.com/parallaxsecond/rust-tss-esapi/issues/102)
- Allow Context to be unwrapped to ESYS\_CONTEXT [\#50](https://github.com/parallaxsecond/rust-tss-esapi/issues/50)
- Create a generic buffer implementation [\#112](https://github.com/parallaxsecond/rust-tss-esapi/pull/112) ([ionut-arm](https://github.com/ionut-arm))
- Added more tr APIs as context methods. [\#111](https://github.com/parallaxsecond/rust-tss-esapi/pull/111) ([Superhepper](https://github.com/Superhepper))

**Closed issues:**

- Handle breaking changes in tpm2-tss from 2.4.0 [\#80](https://github.com/parallaxsecond/rust-tss-esapi/issues/80)

**Merged pull requests:**

- Bump version to 4.0.7-alpha.1 [\#116](https://github.com/parallaxsecond/rust-tss-esapi/pull/116) ([ionut-arm](https://github.com/ionut-arm))
- Improve esys handles handling [\#114](https://github.com/parallaxsecond/rust-tss-esapi/pull/114) ([Superhepper](https://github.com/Superhepper))
- Added rust types for handles. [\#108](https://github.com/parallaxsecond/rust-tss-esapi/pull/108) ([Superhepper](https://github.com/Superhepper))
- Convert PcrData to TPML\_DIGEST [\#106](https://github.com/parallaxsecond/rust-tss-esapi/pull/106) ([genofire](https://github.com/genofire))
- First step to support NV operations. [\#104](https://github.com/parallaxsecond/rust-tss-esapi/pull/104) ([Superhepper](https://github.com/Superhepper))

## [4.0.6-alpha.1](https://github.com/parallaxsecond/rust-tss-esapi/tree/4.0.6-alpha.1) (2020-08-03)

[Full Changelog](https://github.com/parallaxsecond/rust-tss-esapi/compare/4.0.5-alpha.1...4.0.6-alpha.1)

**Implemented enhancements:**

- Add functions for more Policy commands [\#95](https://github.com/parallaxsecond/rust-tss-esapi/pull/95) ([puiterwijk](https://github.com/puiterwijk))

**Merged pull requests:**

- Bump version to 4.0.6-alpha.1 [\#107](https://github.com/parallaxsecond/rust-tss-esapi/pull/107) ([ionut-arm](https://github.com/ionut-arm))
- Implement rsa\_encrypt and rsa\_decrypt for TransientKeyContext [\#103](https://github.com/parallaxsecond/rust-tss-esapi/pull/103) ([puiterwijk](https://github.com/puiterwijk))
- Add RSA decryption and encryption to Context [\#101](https://github.com/parallaxsecond/rust-tss-esapi/pull/101) ([puiterwijk](https://github.com/puiterwijk))
- Refactoring Phase 2 [\#100](https://github.com/parallaxsecond/rust-tss-esapi/pull/100) ([Superhepper](https://github.com/Superhepper))
- Fix clippy errors [\#99](https://github.com/parallaxsecond/rust-tss-esapi/pull/99) ([puiterwijk](https://github.com/puiterwijk))
- Remove the aes-256-symdef from TpmtSymdefBuilder [\#98](https://github.com/parallaxsecond/rust-tss-esapi/pull/98) ([puiterwijk](https://github.com/puiterwijk))
- Add get\_capabilities [\#97](https://github.com/parallaxsecond/rust-tss-esapi/pull/97) ([puiterwijk](https://github.com/puiterwijk))
- Refactoring Phase 1 increment 2. [\#96](https://github.com/parallaxsecond/rust-tss-esapi/pull/96) ([Superhepper](https://github.com/Superhepper))
- Refactoring phase 1: [\#94](https://github.com/parallaxsecond/rust-tss-esapi/pull/94) ([Superhepper](https://github.com/Superhepper))

## [4.0.5-alpha.1](https://github.com/parallaxsecond/rust-tss-esapi/tree/4.0.5-alpha.1) (2020-07-02)

[Full Changelog](https://github.com/parallaxsecond/rust-tss-esapi/compare/4.0.4-alpha.1...4.0.5-alpha.1)

**Implemented enhancements:**

- Added policy\_or [\#90](https://github.com/parallaxsecond/rust-tss-esapi/pull/90) ([puiterwijk](https://github.com/puiterwijk))
- Add unsealing [\#89](https://github.com/parallaxsecond/rust-tss-esapi/pull/89) ([puiterwijk](https://github.com/puiterwijk))
- Add TCTI configuration [\#88](https://github.com/parallaxsecond/rust-tss-esapi/pull/88) ([ionut-arm](https://github.com/ionut-arm))

**Merged pull requests:**

- Bump version to 4.0.5-alpha.1 [\#93](https://github.com/parallaxsecond/rust-tss-esapi/pull/93) ([ionut-arm](https://github.com/ionut-arm))
- Add Context.policy\_authorize [\#91](https://github.com/parallaxsecond/rust-tss-esapi/pull/91) ([puiterwijk](https://github.com/puiterwijk))

## [4.0.4-alpha.1](https://github.com/parallaxsecond/rust-tss-esapi/tree/4.0.4-alpha.1) (2020-06-17)

[Full Changelog](https://github.com/parallaxsecond/rust-tss-esapi/compare/4.0.3-alpha.1...4.0.4-alpha.1)

**Implemented enhancements:**

- the trait `std::error::Error` is not implemented for `tss\_esapi::response\_code::Error [\#77](https://github.com/parallaxsecond/rust-tss-esapi/issues/77)
- Added get\_policy\_digest API [\#81](https://github.com/parallaxsecond/rust-tss-esapi/pull/81) ([Superhepper](https://github.com/Superhepper))
- Minor change to remove usage of raw TSS type in load\_external API. [\#79](https://github.com/parallaxsecond/rust-tss-esapi/pull/79) ([Superhepper](https://github.com/Superhepper))
- Implement std::error::Error on Error [\#78](https://github.com/parallaxsecond/rust-tss-esapi/pull/78) ([ionut-arm](https://github.com/ionut-arm))

**Merged pull requests:**

- Bump version to 4.0.4-alpha.1 [\#83](https://github.com/parallaxsecond/rust-tss-esapi/pull/83) ([ionut-arm](https://github.com/ionut-arm))

## [4.0.3-alpha.1](https://github.com/parallaxsecond/rust-tss-esapi/tree/4.0.3-alpha.1) (2020-06-03)

[Full Changelog](https://github.com/parallaxsecond/rust-tss-esapi/compare/4.0.2-alpha.1...4.0.3-alpha.1)

**Implemented enhancements:**

- Add ECDSA support [\#68](https://github.com/parallaxsecond/rust-tss-esapi/issues/68)
- Bump to 4.0.3-alpha.1 [\#76](https://github.com/parallaxsecond/rust-tss-esapi/pull/76) ([hug-dev](https://github.com/hug-dev))
- Also add the TSS2-MU library [\#74](https://github.com/parallaxsecond/rust-tss-esapi/pull/74) ([puiterwijk](https://github.com/puiterwijk))
- Hash method [\#72](https://github.com/parallaxsecond/rust-tss-esapi/pull/72) ([Superhepper](https://github.com/Superhepper))

**Closed issues:**

- Missing Convert PcrSelections into TPML\_PCR\_SELECTION [\#73](https://github.com/parallaxsecond/rust-tss-esapi/issues/73)
- Add policy pcr support. [\#64](https://github.com/parallaxsecond/rust-tss-esapi/issues/64)
- Add Quote support [\#52](https://github.com/parallaxsecond/rust-tss-esapi/issues/52)

**Merged pull requests:**

- Pcr read return improvement [\#71](https://github.com/parallaxsecond/rust-tss-esapi/pull/71) ([Superhepper](https://github.com/Superhepper))

## [4.0.2-alpha.1](https://github.com/parallaxsecond/rust-tss-esapi/tree/4.0.2-alpha.1) (2020-05-11)

[Full Changelog](https://github.com/parallaxsecond/rust-tss-esapi/compare/4.0.1-alpha.1...4.0.2-alpha.1)

**Fixed bugs:**

- Fix ECDSA signature variant name [\#70](https://github.com/parallaxsecond/rust-tss-esapi/pull/70) ([ionut-arm](https://github.com/ionut-arm))

## [4.0.1-alpha.1](https://github.com/parallaxsecond/rust-tss-esapi/tree/4.0.1-alpha.1) (2020-05-06)

[Full Changelog](https://github.com/parallaxsecond/rust-tss-esapi/compare/4.0.0-alpha.1...4.0.1-alpha.1)

**Implemented enhancements:**

- Add support for elliptic curves for transient context [\#69](https://github.com/parallaxsecond/rust-tss-esapi/pull/69) ([ionut-arm](https://github.com/ionut-arm))

## [4.0.0-alpha.1](https://github.com/parallaxsecond/rust-tss-esapi/tree/4.0.0-alpha.1) (2020-05-04)

[Full Changelog](https://github.com/parallaxsecond/rust-tss-esapi/compare/3.0.2...4.0.0-alpha.1)

**Implemented enhancements:**

- Create Rust-native TPM2\_ALG\_ID wrapper [\#40](https://github.com/parallaxsecond/rust-tss-esapi/issues/40)
- Refactor `Cipher`; Add `quote` method [\#67](https://github.com/parallaxsecond/rust-tss-esapi/pull/67) ([ionut-arm](https://github.com/ionut-arm))
- Link to the Contribution Guidelines [\#65](https://github.com/parallaxsecond/rust-tss-esapi/pull/65) ([hug-dev](https://github.com/hug-dev))
- Pcr selection improvement [\#63](https://github.com/parallaxsecond/rust-tss-esapi/pull/63) ([Superhepper](https://github.com/Superhepper))
- Improve RSA parameter creation [\#56](https://github.com/parallaxsecond/rust-tss-esapi/pull/56) ([ionut-arm](https://github.com/ionut-arm))

**Closed issues:**

- Feature API compliance [\#61](https://github.com/parallaxsecond/rust-tss-esapi/issues/61)

**Merged pull requests:**

- Update the way copyright is displayed [\#62](https://github.com/parallaxsecond/rust-tss-esapi/pull/62) ([ionut-arm](https://github.com/ionut-arm))
- Improved handling of TPM2\_ALG\_ID. [\#60](https://github.com/parallaxsecond/rust-tss-esapi/pull/60) ([Superhepper](https://github.com/Superhepper))
- Thin wrapper around Esys\_PCR\_Read [\#57](https://github.com/parallaxsecond/rust-tss-esapi/pull/57) ([Superhepper](https://github.com/Superhepper))
- Added more TPM Resource API:s [\#54](https://github.com/parallaxsecond/rust-tss-esapi/pull/54) ([Superhepper](https://github.com/Superhepper))

## [3.0.2](https://github.com/parallaxsecond/rust-tss-esapi/tree/3.0.2) (2020-03-20)

[Full Changelog](https://github.com/parallaxsecond/rust-tss-esapi/compare/3.0.1...3.0.2)

**Implemented enhancements:**

- \[Improvement\] Provide access to the Esys\_TR\_\* methods. [\#47](https://github.com/parallaxsecond/rust-tss-esapi/issues/47)

**Merged pull requests:**

- Bumping version number [\#51](https://github.com/parallaxsecond/rust-tss-esapi/pull/51) ([ionut-arm](https://github.com/ionut-arm))
- Added the tr\_get name function [\#48](https://github.com/parallaxsecond/rust-tss-esapi/pull/48) ([Superhepper](https://github.com/Superhepper))

## [3.0.1](https://github.com/parallaxsecond/rust-tss-esapi/tree/3.0.1) (2020-03-11)

[Full Changelog](https://github.com/parallaxsecond/rust-tss-esapi/compare/3.0.0...3.0.1)

**Fixed bugs:**

- Fix building for docs.rs [\#45](https://github.com/parallaxsecond/rust-tss-esapi/pull/45) ([ionut-arm](https://github.com/ionut-arm))

## [3.0.0](https://github.com/parallaxsecond/rust-tss-esapi/tree/3.0.0) (2020-03-10)

[Full Changelog](https://github.com/parallaxsecond/rust-tss-esapi/compare/2.0.0...3.0.0)

**Implemented enhancements:**

- Implement TestParms function [\#38](https://github.com/parallaxsecond/rust-tss-esapi/issues/38)
- Add TestParms method [\#42](https://github.com/parallaxsecond/rust-tss-esapi/pull/42) ([ionut-arm](https://github.com/ionut-arm))
- Remove explicit handles in StartSessionAuth [\#41](https://github.com/parallaxsecond/rust-tss-esapi/pull/41) ([ionut-arm](https://github.com/ionut-arm))
- Trim Context constructor; Improve ctx creation [\#39](https://github.com/parallaxsecond/rust-tss-esapi/pull/39) ([ionut-arm](https://github.com/ionut-arm))
- Add stronger lints [\#34](https://github.com/parallaxsecond/rust-tss-esapi/pull/34) ([hug-dev](https://github.com/hug-dev))

**Fixed bugs:**

- Handle TPMS\_CONTEXT more robustly [\#36](https://github.com/parallaxsecond/rust-tss-esapi/issues/36)

**Merged pull requests:**

- Bump version to 3.0.0 [\#44](https://github.com/parallaxsecond/rust-tss-esapi/pull/44) ([ionut-arm](https://github.com/ionut-arm))

## [2.0.0](https://github.com/parallaxsecond/rust-tss-esapi/tree/2.0.0) (2020-01-27)

[Full Changelog](https://github.com/parallaxsecond/rust-tss-esapi/compare/1.0.1...2.0.0)

**Implemented enhancements:**

- Remove 'unimplemented' use and fix lints [\#33](https://github.com/parallaxsecond/rust-tss-esapi/pull/33) ([ionut-arm](https://github.com/ionut-arm))

## [1.0.1](https://github.com/parallaxsecond/rust-tss-esapi/tree/1.0.1) (2020-01-17)

[Full Changelog](https://github.com/parallaxsecond/rust-tss-esapi/compare/1.0.0...1.0.1)

**Merged pull requests:**

- Improve docs [\#32](https://github.com/parallaxsecond/rust-tss-esapi/pull/32) ([ionut-arm](https://github.com/ionut-arm))

## [1.0.0](https://github.com/parallaxsecond/rust-tss-esapi/tree/1.0.0) (2020-01-15)

[Full Changelog](https://github.com/parallaxsecond/rust-tss-esapi/compare/0.6.0...1.0.0)

**Implemented enhancements:**

- Fix clippy warnings [\#29](https://github.com/parallaxsecond/rust-tss-esapi/pull/29) ([ionut-arm](https://github.com/ionut-arm))

**Fixed bugs:**

- Multi-threading support [\#7](https://github.com/parallaxsecond/rust-tss-esapi/issues/7)

**Merged pull requests:**

- Adding metadata and bumping to 1.0.0 [\#28](https://github.com/parallaxsecond/rust-tss-esapi/pull/28) ([ionut-arm](https://github.com/ionut-arm))

## [0.6.0](https://github.com/parallaxsecond/rust-tss-esapi/tree/0.6.0) (2020-01-15)

[Full Changelog](https://github.com/parallaxsecond/rust-tss-esapi/compare/0.5.0...0.6.0)

**Implemented enhancements:**

- Write unit tests [\#10](https://github.com/parallaxsecond/rust-tss-esapi/issues/10)
- Add TransientObjectContext integration tests [\#26](https://github.com/parallaxsecond/rust-tss-esapi/pull/26) ([hug-dev](https://github.com/hug-dev))
- Add integration tests [\#25](https://github.com/parallaxsecond/rust-tss-esapi/pull/25) ([ionut-arm](https://github.com/ionut-arm))

**Merged pull requests:**

- Add multithreading docs [\#27](https://github.com/parallaxsecond/rust-tss-esapi/pull/27) ([ionut-arm](https://github.com/ionut-arm))

## [0.5.0](https://github.com/parallaxsecond/rust-tss-esapi/tree/0.5.0) (2020-01-09)

[Full Changelog](https://github.com/parallaxsecond/rust-tss-esapi/compare/0.4.0...0.5.0)

**Implemented enhancements:**

- Use libloading to load the TSS libraries [\#14](https://github.com/parallaxsecond/rust-tss-esapi/issues/14)
- Improve the interface of TransientObjectContext [\#8](https://github.com/parallaxsecond/rust-tss-esapi/issues/8)
- Deny compilation to chosen rustc lints [\#22](https://github.com/parallaxsecond/rust-tss-esapi/pull/22) ([hug-dev](https://github.com/hug-dev))
- Improve TransientObjectContext interface [\#19](https://github.com/parallaxsecond/rust-tss-esapi/pull/19) ([ionut-arm](https://github.com/ionut-arm))
- Improve usage of unsafe blocks [\#18](https://github.com/parallaxsecond/rust-tss-esapi/pull/18) ([ionut-arm](https://github.com/ionut-arm))
- Improve usage of unwrap and expect [\#17](https://github.com/parallaxsecond/rust-tss-esapi/pull/17) ([ionut-arm](https://github.com/ionut-arm))
- Add wrapper crate-specific errors [\#15](https://github.com/parallaxsecond/rust-tss-esapi/pull/15) ([ionut-arm](https://github.com/ionut-arm))

**Fixed bugs:**

- Implement error handling for our wrapping layer [\#3](https://github.com/parallaxsecond/rust-tss-esapi/issues/3)
- Investigate use of `unsafe` and panicking [\#2](https://github.com/parallaxsecond/rust-tss-esapi/issues/2)
- Add pkg-config in the build script [\#16](https://github.com/parallaxsecond/rust-tss-esapi/pull/16) ([hug-dev](https://github.com/hug-dev))

**Closed issues:**

- Add documentation [\#9](https://github.com/parallaxsecond/rust-tss-esapi/issues/9)

**Merged pull requests:**

- Add documentation [\#20](https://github.com/parallaxsecond/rust-tss-esapi/pull/20) ([ionut-arm](https://github.com/ionut-arm))

## [0.4.0](https://github.com/parallaxsecond/rust-tss-esapi/tree/0.4.0) (2019-12-12)

[Full Changelog](https://github.com/parallaxsecond/rust-tss-esapi/compare/0.3.0...0.4.0)

**Fixed bugs:**

- Fix session handling [\#12](https://github.com/parallaxsecond/rust-tss-esapi/pull/12) ([ionut-arm](https://github.com/ionut-arm))

## [0.3.0](https://github.com/parallaxsecond/rust-tss-esapi/tree/0.3.0) (2019-12-11)

[Full Changelog](https://github.com/parallaxsecond/rust-tss-esapi/compare/0.2.0...0.3.0)

**Implemented enhancements:**

- Fix various issues [\#11](https://github.com/parallaxsecond/rust-tss-esapi/pull/11) ([ionut-arm](https://github.com/ionut-arm))

## [0.2.0](https://github.com/parallaxsecond/rust-tss-esapi/tree/0.2.0) (2019-12-11)

[Full Changelog](https://github.com/parallaxsecond/rust-tss-esapi/compare/0.1.0...0.2.0)

**Implemented enhancements:**

- Add a CI job for tests with TPM simulation server [\#5](https://github.com/parallaxsecond/rust-tss-esapi/pull/5) ([hug-dev](https://github.com/hug-dev))
- Add transient object context [\#4](https://github.com/parallaxsecond/rust-tss-esapi/pull/4) ([ionut-arm](https://github.com/ionut-arm))

**Merged pull requests:**

- Improve Context interface [\#1](https://github.com/parallaxsecond/rust-tss-esapi/pull/1) ([ionut-arm](https://github.com/ionut-arm))

## [0.1.0](https://github.com/parallaxsecond/rust-tss-esapi/tree/0.1.0) (2019-12-05)

[Full Changelog](https://github.com/parallaxsecond/rust-tss-esapi/compare/932f4d955c814373ded28cdaee83486586986e16...0.1.0)



\* *This Changelog was automatically generated by [github_changelog_generator](https://github.com/github-changelog-generator/github-changelog-generator)*
