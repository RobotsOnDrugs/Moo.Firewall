#![deny(clippy::implicit_return)]
#![allow(clippy::needless_return)]

use std::fs::OpenOptions;
use std::os::windows::fs::OpenOptionsExt;

use crate::configuration::config_file::get_rules_from_config_file;
use clap::value_parser;
use clap::Arg;
use clap::Command;
use serde::Deserialize;
use windows_wfp::IpAddrMask;

#[derive(Debug, Clone, Deserialize)]
struct RuleRaw
{
	pub(crate) name: String,
	pub(crate) service_name: Option<String>,
	pub(crate) remote_ip: Option<String>,
	pub(crate) weight: Option<u64>,
	pub(crate) protocol: Option<String>,
	pub(crate) app_path: Option<String>,
	pub(crate) inbound: Option<bool>,
	pub(crate) permit: Option<bool>
}

#[derive(Debug, Clone, Deserialize)]
struct SettingsRaw { rules: Vec<RuleRaw>, pub(crate) ephemeral: bool, pub(crate) delete_rule_id: Option<u64>, pub(crate) wait_time: u64 }

#[derive(Debug, Clone)]
pub(crate) struct Settings { pub(crate) rules: Vec<windows_wfp::FilterRule>, pub(crate) ephemeral: bool, pub(crate) delete_rule_id: Option<u64>, pub(crate) wait_time: u64 }

pub trait FilterRuleExt { fn display_multiline(&self, _: Option<u64>) -> String; }
impl FilterRuleExt for windows_wfp::FilterRule
{
	fn display_multiline(&self, filter_id: Option<u64>) -> String
	{
		let mut display_string = String::new();
		let mut lines = vec![];
		let display_id = filter_id.map(|id| format!(" (ID: {id})")).unwrap_or_default();
		lines.push(format!("Filter Rule: {}{display_id}\n", &self.name));
		lines.push(format!("Service Name: {}", self.service_name.as_ref().unwrap_or(&"<None>".to_string())));
		lines.push(format!("Direction: {}", &self.direction.to_string()));
		lines.push(format!("Action: {}", &self.action.to_string()));
		lines.push(format!("Protocol: {}", &self.protocol.map(|proto| proto.to_string()).unwrap_or("<All>".to_string())));
		lines.push(format!("Weight: 0x{:X}", &self.weight));
		let formatted_ip_port = |mask: &Option<IpAddrMask>, port: &Option<u16>|
			{
				mask.as_ref().map(|mask| (mask.addr, mask.prefix_len))
					.map(|(addr, prefix)| format!("{addr}/{prefix}")).unwrap_or("<All>".to_string())
					+ ":" +
					&port.map(|port| port.to_string()).unwrap_or("<All>".to_string()).to_string()
			};
		lines.push(format!("Local Subnet/Port: {}", formatted_ip_port(&self.local_ip, &self.local_port)));
		lines.push(format!("Remote Subnet/Port: {}", formatted_ip_port(&self.remote_ip, &self.remote_port)));
		lines.push(format!("Application: {}", self.app_path.as_ref().map(|path| path.display().to_string()).unwrap_or("<All>".to_string())));
		lines.push(format!("Application Container SID: {}", &self.app_container_sid.clone().unwrap_or("<N/A>".to_string())));
		display_string.push_str(&lines[0]);
		for line in &lines[1..lines.len() - 1]
		{
			display_string.push_str("\t-> ");
			display_string.push_str(&line);
			display_string.push_str("\n");
		}
		display_string.push_str(&*("\t-> ".to_owned() + &lines[lines.len() - 1]));

		return display_string;
	}
}

mod config_file;
mod args;

pub(crate) fn get_settings() -> Result<Settings, anyhow::Error>
{
	let arguments = &
	[
		Arg::new("ephemeral").long("ephemeral").short('e').help("Set the filter to be deleted when the application exits. Useful for testing.").required(false).action(clap::ArgAction::SetTrue),
		Arg::new("delete_rule_id").long("delete-rule-id").short('d').help("Delete a rule by ID.").required(false).value_parser(value_parser!(u64).range(..)).action(clap::ArgAction::Set),
		Arg::new("wait_time").long("wait-time").short('w').help("Wait this many seconds before exiting.").required(false).value_parser(value_parser!(u64).range(..)).action(clap::ArgAction::Set)
	];

	let mut settings_file = OpenOptions::new().read(true).write(false).share_mode(0).open("rules.toml")?;
	let settings_from_config = get_rules_from_config_file(&mut settings_file)?;
	let matches = Command::new("Moo.Firewall").args(arguments).get_matches();
	if let Ok(run_settings) = args::get_run_settings_from_args(matches)
	{
		let settings = Settings
		{
			rules: settings_from_config.rules,
			ephemeral: run_settings.ephemeral.unwrap_or(false),
			delete_rule_id: run_settings.delete_rule_id,
			wait_time: run_settings.wait_time
		};
		return Ok(settings);
	};
	return Ok(settings_from_config);
}