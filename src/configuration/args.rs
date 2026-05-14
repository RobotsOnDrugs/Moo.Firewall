#![deny(clippy::implicit_return)]
#![allow(clippy::needless_return)]

use clap::ArgMatches;

#[derive(Debug, Clone)]
pub(crate) struct RunSettings
{
	pub(crate) ephemeral: Option<bool>,
	pub(crate) delete_rule_id: Option<u64>,
	pub(crate) wait_time: u64
}

pub(crate) fn get_run_settings_from_args(matches: ArgMatches) -> Result<RunSettings, anyhow::Error>
{
	let ephemeral = matches.get_flag("ephemeral");
	let delete_rule_id = matches.get_one::<u64>("delete_rule_id").map(|id| *id);
	let wait_time = matches.get_one::<u64>("wait_time").map(|id| *id).unwrap_or(0u64);
	let run_settings = RunSettings
	{
		ephemeral: Some(ephemeral),
		delete_rule_id,
		wait_time
	};
	return Ok(run_settings);
}