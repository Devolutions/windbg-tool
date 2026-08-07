use crate::jobs::JobRegistry;
use crate::targets::TargetRegistry;
use crate::ttd_replay::SessionRegistry;

#[derive(Default)]
pub struct ServiceState {
    pub ttd: SessionRegistry,
    pub targets: TargetRegistry,
    pub jobs: JobRegistry,
}
