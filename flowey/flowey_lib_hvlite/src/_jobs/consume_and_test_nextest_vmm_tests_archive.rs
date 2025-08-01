// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Run a pre-built cargo-nextest based VMM tests archive.

use crate::build_guest_test_uefi::GuestTestUefiOutput;
use crate::build_nextest_vmm_tests::NextestVmmTestsArchive;
use crate::build_openvmm::OpenvmmOutput;
use crate::build_pipette::PipetteOutput;
use crate::build_tmk_vmm::TmkVmmOutput;
use crate::build_tmks::TmksOutput;
use crate::install_vmm_tests_deps::VmmTestsDepSelections;
use crate::run_cargo_nextest_run::NextestProfile;
use flowey::node::prelude::*;
use std::collections::BTreeMap;
use vmm_test_images::KnownTestArtifacts;

#[derive(Serialize, Deserialize)]
pub struct VmmTestsDepArtifacts {
    pub openvmm: Option<ReadVar<OpenvmmOutput>>,
    pub pipette_windows: Option<ReadVar<PipetteOutput>>,
    pub pipette_linux_musl: Option<ReadVar<PipetteOutput>>,
    pub guest_test_uefi: Option<ReadVar<GuestTestUefiOutput>>,
    pub artifact_dir_openhcl_igvm_files: Option<ReadVar<PathBuf>>,
    pub tmks: Option<ReadVar<TmksOutput>>,
    pub tmk_vmm: Option<ReadVar<TmkVmmOutput>>,
    pub tmk_vmm_linux_musl: Option<ReadVar<TmkVmmOutput>>,
}

flowey_request! {
    pub struct Params {
        /// Friendly label for report JUnit test results
        pub junit_test_label: String,
        /// Existing VMM tests archive
        pub nextest_vmm_tests_archive: ReadVar<NextestVmmTestsArchive>,
        /// What target VMM tests were compiled for (determines required deps).
        pub target: target_lexicon::Triple,
        /// Nextest profile to use when running the source code
        pub nextest_profile: NextestProfile,
        /// Nextest test filter expression.
        pub nextest_filter_expr: Option<String>,
        /// Artifacts corresponding to required test dependencies
        pub dep_artifact_dirs: VmmTestsDepArtifacts,
        /// Test artifacts to download
        pub test_artifacts: Vec<KnownTestArtifacts>,

        /// Whether the job should fail if any test has failed
        pub fail_job_on_test_fail: bool,
        /// If provided, also publish junit.xml test results as an artifact.
        pub artifact_dir: Option<ReadVar<PathBuf>>,
        pub done: WriteVar<SideEffect>,
    }
}

new_simple_flow_node!(struct Node);

impl SimpleFlowNode for Node {
    type Request = Params;

    fn imports(ctx: &mut ImportCtx<'_>) {
        ctx.import::<crate::artifact_openhcl_igvm_from_recipe_extras::resolve::Node>();
        ctx.import::<crate::artifact_openhcl_igvm_from_recipe::resolve::Node>();
        ctx.import::<crate::download_openvmm_vmm_tests_artifacts::Node>();
        ctx.import::<crate::init_openvmm_magicpath_uefi_mu_msvm::Node>();
        ctx.import::<crate::install_vmm_tests_deps::Node>();
        ctx.import::<crate::init_vmm_tests_env::Node>();
        ctx.import::<crate::test_nextest_vmm_tests_archive::Node>();
        ctx.import::<flowey_lib_common::publish_test_results::Node>();
    }

    fn process_request(request: Self::Request, ctx: &mut NodeCtx<'_>) -> anyhow::Result<()> {
        let Params {
            junit_test_label,
            nextest_vmm_tests_archive,
            target,
            nextest_profile,
            nextest_filter_expr,
            dep_artifact_dirs,
            test_artifacts,
            fail_job_on_test_fail,
            artifact_dir,
            done,
        } = request;

        // use an ad-hoc, step-local dir as a staging ground for test content
        let test_content_dir = ctx.emit_rust_stepv("creating new test content dir", |_| {
            |_| Ok(std::env::current_dir()?.absolute()?)
        });

        let VmmTestsDepArtifacts {
            openvmm: register_openvmm,
            pipette_windows: register_pipette_windows,
            pipette_linux_musl: register_pipette_linux_musl,
            guest_test_uefi: register_guest_test_uefi,
            artifact_dir_openhcl_igvm_files,
            tmks: register_tmks,
            tmk_vmm: register_tmk_vmm,
            tmk_vmm_linux_musl: register_tmk_vmm_linux_musl,
        } = dep_artifact_dirs;

        let register_openhcl_igvm_files = artifact_dir_openhcl_igvm_files.map(|artifact_dir| {
            ctx.reqv(
                |v| crate::artifact_openhcl_igvm_from_recipe::resolve::Request {
                    artifact_dir,
                    igvm_files: v,
                },
            )
        });

        ctx.req(crate::download_openvmm_vmm_tests_artifacts::Request::Download(test_artifacts));

        let disk_images_dir =
            ctx.reqv(crate::download_openvmm_vmm_tests_artifacts::Request::GetDownloadFolder);

        ctx.req(crate::install_vmm_tests_deps::Request::Select(
            match target.operating_system {
                target_lexicon::OperatingSystem::Windows => VmmTestsDepSelections::Windows {
                    hyperv: true,
                    whp: true,
                    hardware_isolation: false,
                },
                target_lexicon::OperatingSystem::Linux => VmmTestsDepSelections::Linux,
                os => anyhow::bail!("unsupported target operating system: {os}"),
            },
        ));

        let pre_run_deps = vec![ctx.reqv(crate::install_vmm_tests_deps::Request::Install)];

        let (test_log_path, get_test_log_path) = ctx.new_var();

        let extra_env = ctx.reqv(|v| crate::init_vmm_tests_env::Request {
            test_content_dir,
            vmm_tests_target: target.clone(),
            register_openvmm,
            register_pipette_windows,
            register_pipette_linux_musl,
            register_guest_test_uefi,
            register_tmks,
            register_tmk_vmm,
            register_tmk_vmm_linux_musl,
            disk_images_dir: Some(disk_images_dir),
            register_openhcl_igvm_files,
            get_test_log_path: Some(get_test_log_path),
            get_env: v,
            use_relative_paths: false,
        });

        let results = ctx.reqv(|v| crate::test_nextest_vmm_tests_archive::Request {
            nextest_archive_file: nextest_vmm_tests_archive,
            nextest_profile,
            nextest_filter_expr,
            nextest_working_dir: None,
            nextest_config_file: None,
            nextest_bin: None,
            target: None,
            extra_env,
            pre_run_deps,
            results: v,
        });

        // Bind the externally generated output paths together with the results
        // to create a dependency on the VMM tests having actually run.
        let test_log_path = test_log_path.depending_on(ctx, &results);

        let junit_xml = results.map(ctx, |r| r.junit_xml);
        let reported_results = ctx.reqv(|v| flowey_lib_common::publish_test_results::Request {
            junit_xml,
            test_label: junit_test_label,
            attachments: BTreeMap::from([("logs".to_string(), (test_log_path, false))]),
            output_dir: artifact_dir,
            done: v,
        });

        ctx.emit_rust_step("report test results to overall pipeline status", |ctx| {
            reported_results.claim(ctx);
            done.claim(ctx);

            let results = results.clone().claim(ctx);
            move |rt| {
                let results = rt.read(results);
                if results.all_tests_passed {
                    log::info!("all tests passed!");
                } else {
                    if fail_job_on_test_fail {
                        anyhow::bail!("encountered test failures.")
                    } else {
                        log::error!("encountered test failures.")
                    }
                }

                Ok(())
            }
        });

        Ok(())
    }
}
