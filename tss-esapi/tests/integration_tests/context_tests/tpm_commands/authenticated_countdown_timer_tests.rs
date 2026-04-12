// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod test_act_set_timeout {
    // ACT (Authenticated Countdown Timer) is not universally supported.
    // This test is marked as ignored since it requires TPM ACT support.
    #[test]
    #[ignore]
    fn test_act_set_timeout() {
        // ACT handles are vendor-specific and may not be available on all TPMs.
        // This test is intentionally ignored as it requires specific hardware support.
    }
}
