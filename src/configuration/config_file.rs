#![deny(clippy::implicit_return)]
#![allow(clippy::needless_return)]

use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

use anyhow::anyhow;
use crate::configuration::Settings;
use crate::configuration::SettingsRaw;

pub(crate) fn get_rules_from_config_file(file: &mut File) -> Result<Settings, anyhow::Error>
{
	let mut settings_string = String::new();
	file.read_to_string(&mut settings_string)?;
	let settings_inner = toml::from_str::<SettingsRaw>(&settings_string)?;
	let rules_inner = settings_inner.rules;
	let mut filter_rules = vec![];
	for rule_raw in rules_inner
	{
		let direction = match rule_raw.inbound
		{
			None => windows_wfp::Direction::Outbound,
			Some(direction) =>
			{
				match direction
				{
					true => windows_wfp::Direction::Inbound,
					false => windows_wfp::Direction::Outbound
				}
			}
		};
		let action = match rule_raw.permit
		{
			None => windows_wfp::Action::Block,
			Some(action) =>
			{
				match action
				{
					true => windows_wfp::Action::Permit,
					false => windows_wfp::Action::Block
				}
			}
		};
		let mut rule = windows_wfp::FilterRule::new(&rule_raw.name, direction, action);
		rule.service_name = rule_raw.service_name.clone();
		rule.remote_ip = match rule_raw.clone().remote_ip
		{
			None => None,
			Some(ip) => match windows_wfp::IpAddrMask::from_cidr(&ip)
			{
				Ok(ip) => Some(ip),
				Err(err_msg) =>
				{
					match ip.is_empty()
					{
						true => None,
						false => return Err(anyhow!(err_msg))
					}
				}
			}
		};
		let weight = match rule_raw.clone().weight
		{
			None =>
			{
				match action
				{
					windows_wfp::Action::Permit => windows_wfp::FilterWeight::DefaultPermit.value(),
					windows_wfp::Action::Block => windows_wfp::FilterWeight::DefaultBlock.value()
				}
			}
			Some(weight) => weight
		};
		rule.weight = weight;
		rule.protocol = match rule_raw.clone().protocol
		{
			None => None,
			Some(protocol) => match protocol.to_lowercase().as_str()
			{
				"hopopt" => Some(windows_wfp::Protocol::Hopopt),
				"icmp" => Some(windows_wfp::Protocol::Icmp),
				"igmp" => Some(windows_wfp::Protocol::Igmp),
				"tcp" => Some(windows_wfp::Protocol::Tcp),
				"udp" => Some(windows_wfp::Protocol::Udp),
				"gre" => Some(windows_wfp::Protocol::Gre),
				"esp" => Some(windows_wfp::Protocol::Esp),
				"ah" => Some(windows_wfp::Protocol::Ah),
				"icmpv6" => Some(windows_wfp::Protocol::Icmpv6),
				_ => return Err(anyhow!("{protocol} is not a valid protocol"))
			}
		};
		rule.app_path = match rule_raw.clone().app_path
		{
			None => None,
			Some(path) =>
			{
				if path.is_empty() { None }
				else
				{
					let path = PathBuf::from(path);
					if path.exists()
					{
						if !path.is_file() { return Err(anyhow!("{} is not a file.", path.display())); }
						Some(path)
					} else { return Err(anyhow!("{} does not exist.", path.display())); }
				}
			}
		};
		filter_rules.push(rule);
	}
	let all_settings = Settings
	{
		rules: filter_rules,
		ephemeral: settings_inner.ephemeral,
		delete_rule_id: settings_inner.delete_rule_id,
		wait_time: settings_inner.wait_time,
	};
	Ok(all_settings)
}