#![deny(clippy::implicit_return)]
#![allow(clippy::needless_return)]

use std::fs::OpenOptions;
use std::os::windows::fs::OpenOptionsExt;

use crate::configuration::config_file::get_rules_from_config_file;
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
struct SettingsRaw { rules: Vec<RuleRaw>, ephemeral: bool, delete_rules: bool }

#[derive(Debug, Clone)]
pub(crate) struct Settings { pub(crate) rules: Vec<windows_wfp::FilterRule>, pub(crate) ephemeral: bool, pub(crate) delete_rules: bool }
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
		for line in &lines[1..lines.len() - 2]
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
		// Arg::new("delete_rules").long("delete-rules").short('d').help("Delete rules supplied instead of").required(false).action(clap::ArgAction::SetTrue),
		Arg::new("name").long("name").short('n').help("Name of the filter.").num_args(1).required(false).action(clap::ArgAction::Set),
		Arg::new("service_name").long("service-name").short('s').help("Name of the service associated with the filter. Typically unused.").num_args(1).required(false).action(clap::ArgAction::Set),
		Arg::new("inbound").long("inbound").short('i').help("Filter on inbound connections instead of outbound.").required(false).action(clap::ArgAction::SetTrue),
		Arg::new("remote_ip").long("remote-ip").short('r').help("The remote IP to filter in CIDR notation (e.g., 192.168.1.1/32).").num_args(1).required(false).action(clap::ArgAction::Set),
		Arg::new("permit").long("permit").short('p').help("Set the filter to permit instead of block.").action(clap::ArgAction::SetTrue),
		Arg::new("weight").long("weight").short('w').help("The weight of the filter. Anything that can be parsed as an unsigned 64-bit integer is valid.").num_args(1).required(false).action(clap::ArgAction::Set),
		Arg::new("protocol").long("protocol").short('l').help("The protocol to filter on. Defaults to all protocols.").num_args(1).required(false).action(clap::ArgAction::Set),
		Arg::new("app_path").long("app-path").short('a').help("The path of the application to filter on. Defaults to all applications.").required(false).num_args(1).action(clap::ArgAction::Set),
		Arg::new("ephemeral").long("ephemeral").short('e').help("Set the filter to be deleted when the application exits. Useful for testing.").required(false).action(clap::ArgAction::SetTrue),
	];

	let mut all_rules = vec![];
	let matches = Command::new("Moo.Firewall").args(arguments).get_matches();
	let ephemeral = matches.get_flag("ephemeral");
	// let delete_rules = matches.get_flag("delete_rules");
	let delete_rules = false;
	if let Some(settings) = args::get_rule_from_args(matches)?
	{
		all_rules.push(settings);
		let settings = Settings { rules: all_rules, ephemeral, delete_rules };
		return Ok(settings);
	};

	let mut settings_file = OpenOptions::new().read(true).write(false).share_mode(0).open("rules.toml")?;
	return Ok(get_rules_from_config_file(&mut settings_file)?);
}