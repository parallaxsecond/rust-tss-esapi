// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    Context, Result, ReturnCode,
    context::handle_manager::HandleDropAction,
    handles::{AuthHandle, KeyHandle, ObjectHandle},
    interface_types::{
        YesNo,
        algorithm::HashingAlgorithm,
        reserved_handles::{Enables, Hierarchy, HierarchyAuth},
    },
    structures::{
        Auth, CreatePrimaryKeyResult, CreationData, CreationTicket, Data, Digest, PcrSelectionList,
        Public, SensitiveCreate, SensitiveData,
    },
    tss2_esys::{
        Esys_ChangeEPS, Esys_ChangePPS, Esys_Clear, Esys_ClearControl, Esys_CreatePrimary,
        Esys_HierarchyChangeAuth, Esys_HierarchyControl, Esys_SetPrimaryPolicy,
    },
};
use log::error;
use std::convert::{TryFrom, TryInto};
use std::ptr::null_mut;

impl Context {
    /// Create a primary key and return the handle.
    ///
    /// The authentication value, initial data, outside info and creation PCRs are passed as slices
    /// which are then converted by the method into TSS native structures.
    ///
    /// # Errors
    /// * if either of the slices is larger than the maximum size of the native objects, a
    ///   `WrongParamSize` wrapper error is returned
    // TODO: Fix when compacting the arguments into a struct
    #[allow(clippy::too_many_arguments)]
    pub fn create_primary(
        &mut self,
        primary_handle: Hierarchy,
        public: Public,
        auth_value: Option<Auth>,
        initial_data: Option<SensitiveData>,
        outside_info: Option<Data>,
        creation_pcrs: Option<PcrSelectionList>,
    ) -> Result<CreatePrimaryKeyResult> {
        let sensitive_create = SensitiveCreate::new(
            auth_value.unwrap_or_default(),
            initial_data.unwrap_or_default(),
        );
        let creation_pcrs = PcrSelectionList::list_from_option(creation_pcrs);

        let mut out_public_ptr = null_mut();
        let mut creation_data_ptr = null_mut();
        let mut creation_hash_ptr = null_mut();
        let mut creation_ticket_ptr = null_mut();
        let mut object_handle = ObjectHandle::None.into();

        ReturnCode::ensure_success(
            unsafe {
                Esys_CreatePrimary(
                    self.mut_context(),
                    ObjectHandle::from(primary_handle).into(),
                    self.required_session_1()?,
                    self.optional_session_2(),
                    self.optional_session_3(),
                    &sensitive_create.try_into()?,
                    &public.try_into()?,
                    &outside_info.unwrap_or_default().into(),
                    &creation_pcrs.into(),
                    &mut object_handle,
                    &mut out_public_ptr,
                    &mut creation_data_ptr,
                    &mut creation_hash_ptr,
                    &mut creation_ticket_ptr,
                )
            },
            |ret| {
                error!("Error in creating primary key: {ret:#010X}");
            },
        )?;
        let out_public_owned = Context::ffi_data_to_owned(out_public_ptr)?;
        let creation_data_owned = Context::ffi_data_to_owned(creation_data_ptr)?;
        let creation_hash_owned = Context::ffi_data_to_owned(creation_hash_ptr)?;
        let creation_ticket_owned = Context::ffi_data_to_owned(creation_ticket_ptr)?;
        let primary_key_handle = KeyHandle::from(object_handle);
        self.handle_manager
            .add_handle(primary_key_handle.into(), HandleDropAction::Flush)?;

        Ok(CreatePrimaryKeyResult {
            key_handle: primary_key_handle,
            out_public: Public::try_from(out_public_owned)?,
            creation_data: CreationData::try_from(creation_data_owned)?,
            creation_hash: Digest::try_from(creation_hash_owned)?,
            creation_ticket: CreationTicket::try_from(creation_ticket_owned)?,
        })
    }

    /// Enables or disables use of a hierarchy.
    ///
    /// # Arguments
    ///
    /// * `enable` - The hierarchy or associated NV storage whose state will be changed.
    /// * `state` - `true` to enable use of the hierarchy, or `false` to disable it.
    ///
    /// # Details
    ///
    /// *From the specification*
    /// > This command enables and disables use of a hierarchy and its associated NV storage. The
    /// > command allows phEnable, phEnableNV, shEnable, and ehEnable to be changed when the proper
    /// > authorization is provided.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tss_esapi::{Context, TctiNameConf};
    /// # use tss_esapi::interface_types::{
    /// #     reserved_handles::Enables, session_handles::AuthSession,
    /// # };
    /// # let mut context = Context::new(
    /// #     TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// # ).expect("Failed to create Context");
    /// context
    ///     .execute_with_session(Some(AuthSession::Password), |ctx| {
    ///         ctx.hierarchy_control(Enables::Endorsement, false)?;
    ///         ctx.hierarchy_control(Enables::Endorsement, true)
    ///     })
    ///     .unwrap();
    /// ```
    pub fn hierarchy_control(&mut self, enable: Enables, state: bool) -> Result<()> {
        ReturnCode::ensure_success(
            unsafe {
                Esys_HierarchyControl(
                    self.mut_context(),
                    ObjectHandle::Platform.into(),
                    self.required_session_1()?,
                    self.optional_session_2(),
                    self.optional_session_3(),
                    ObjectHandle::from(enable).into(),
                    YesNo::from(state).into(),
                )
            },
            |ret| {
                error!("Error controlling hierarchy: {ret:#010X}");
            },
        )
    }

    /// Sets the authorization policy for a hierarchy.
    ///
    /// # Arguments
    ///
    /// * `auth_handle` - The hierarchy whose authorization policy will be changed.
    /// * `auth_policy` - The new authorization policy digest.
    /// * `hash_algorithm` - The hash algorithm used to compute `auth_policy`. An empty policy must
    ///   be paired with [`HashingAlgorithm::Null`].
    ///
    /// # Details
    ///
    /// *From the specification*
    /// > This command allows setting of the authorization policy for the lockout (lockoutPolicy),
    /// > the platform hierarchy (platformPolicy), the storage hierarchy (ownerPolicy), and the
    /// > endorsement hierarchy (endorsementPolicy).
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tss_esapi::{Context, TctiNameConf};
    /// # use tss_esapi::{
    /// #     interface_types::{algorithm::HashingAlgorithm, reserved_handles::HierarchyAuth,
    /// #         session_handles::AuthSession},
    /// #     structures::Digest,
    /// # };
    /// # let mut context = Context::new(
    /// #     TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// # ).expect("Failed to create Context");
    /// context
    ///     .execute_with_session(Some(AuthSession::Password), |ctx| {
    ///         ctx.set_primary_policy(
    ///             HierarchyAuth::Platform,
    ///             Digest::default(),
    ///             HashingAlgorithm::Null,
    ///         )
    ///     })
    ///     .unwrap();
    /// ```
    pub fn set_primary_policy(
        &mut self,
        auth_handle: HierarchyAuth,
        auth_policy: Digest,
        hash_algorithm: HashingAlgorithm,
    ) -> Result<()> {
        ReturnCode::ensure_success(
            unsafe {
                Esys_SetPrimaryPolicy(
                    self.mut_context(),
                    ObjectHandle::from(auth_handle).into(),
                    self.required_session_1()?,
                    self.optional_session_2(),
                    self.optional_session_3(),
                    &auth_policy.into(),
                    hash_algorithm.into(),
                )
            },
            |ret| {
                error!("Error setting primary policy: {ret:#010X}");
            },
        )
    }

    /// Replaces the platform primary seed with a new random value.
    ///
    /// # Arguments
    ///
    /// This command has no command-specific arguments. The first configured session must authorize
    /// the platform hierarchy.
    ///
    /// # Details
    ///
    /// *From the specification*
    /// > This replaces the current platform primary seed (PPS) with a value from the RNG and sets
    /// > platformPolicy to the default initialization value (the Empty Buffer).
    ///
    /// Existing objects in the platform hierarchy can no longer be loaded after this command.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tss_esapi::{Context, TctiNameConf};
    /// # use tss_esapi::interface_types::session_handles::AuthSession;
    /// # let mut context = Context::new(
    /// #     TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// # ).expect("Failed to create Context");
    /// context
    ///     .execute_with_session(Some(AuthSession::Password), |ctx| ctx.change_pps())
    ///     .unwrap();
    /// ```
    pub fn change_pps(&mut self) -> Result<()> {
        ReturnCode::ensure_success(
            unsafe {
                Esys_ChangePPS(
                    self.mut_context(),
                    ObjectHandle::Platform.into(),
                    self.required_session_1()?,
                    self.optional_session_2(),
                    self.optional_session_3(),
                )
            },
            |ret| {
                error!("Error changing platform primary seed: {ret:#010X}");
            },
        )
    }

    /// Replaces the endorsement primary seed with a new random value.
    ///
    /// # Arguments
    ///
    /// This command has no command-specific arguments. The first configured session must authorize
    /// the platform hierarchy.
    ///
    /// # Details
    ///
    /// *From the specification*
    /// > This replaces the current endorsement primary seed (EPS) with a value from the RNG and
    /// > sets the Endorsement hierarchy controls to their default initialization values: ehEnable
    /// > is SET, endorsementAuth and endorsementPolicy are both set to the Empty Buffer. It will
    /// > flush any resident objects (transient or persistent) in the Endorsement hierarchy and not
    /// > allow objects in the hierarchy associated with the previous EPS to be loaded.
    ///
    /// Existing objects in the endorsement hierarchy can no longer be loaded after this command.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tss_esapi::{Context, TctiNameConf};
    /// # use tss_esapi::interface_types::session_handles::AuthSession;
    /// # let mut context = Context::new(
    /// #     TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// # ).expect("Failed to create Context");
    /// context
    ///     .execute_with_session(Some(AuthSession::Password), |ctx| ctx.change_eps())
    ///     .unwrap();
    /// ```
    pub fn change_eps(&mut self) -> Result<()> {
        ReturnCode::ensure_success(
            unsafe {
                Esys_ChangeEPS(
                    self.mut_context(),
                    ObjectHandle::Platform.into(),
                    self.required_session_1()?,
                    self.optional_session_2(),
                    self.optional_session_3(),
                )
            },
            |ret| {
                error!("Error changing endorsement primary seed: {ret:#010X}");
            },
        )
    }

    /// Clear all TPM context associated with a specific Owner
    pub fn clear(&mut self, auth_handle: AuthHandle) -> Result<()> {
        ReturnCode::ensure_success(
            unsafe {
                Esys_Clear(
                    self.mut_context(),
                    auth_handle.into(),
                    self.required_session_1()?,
                    self.optional_session_2(),
                    self.optional_session_3(),
                )
            },
            |ret| {
                error!("Error in clearing TPM hierarchy: {ret:#010X}");
            },
        )
    }

    /// Disable or enable the TPM2_CLEAR command
    pub fn clear_control(&mut self, auth_handle: AuthHandle, disable: bool) -> Result<()> {
        ReturnCode::ensure_success(
            unsafe {
                Esys_ClearControl(
                    self.mut_context(),
                    auth_handle.into(),
                    self.required_session_1()?,
                    self.optional_session_2(),
                    self.optional_session_3(),
                    YesNo::from(disable).into(),
                )
            },
            |ret| {
                error!("Error in controlling clear command: {ret:#010X}");
            },
        )
    }

    /// Change authorization for a hierarchy root
    pub fn hierarchy_change_auth(&mut self, auth_handle: AuthHandle, new_auth: Auth) -> Result<()> {
        ReturnCode::ensure_success(
            unsafe {
                Esys_HierarchyChangeAuth(
                    self.mut_context(),
                    auth_handle.into(),
                    self.required_session_1()?,
                    self.optional_session_2(),
                    self.optional_session_3(),
                    &new_auth.into(),
                )
            },
            |ret| {
                error!("Error changing hierarchy auth: {ret:#010X}");
            },
        )
    }
}
