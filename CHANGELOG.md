# Changelog

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
